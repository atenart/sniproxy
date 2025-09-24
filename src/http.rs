use std::{
    io::{Read, Write},
    net::SocketAddr,
    str,
};

use anyhow::{Result, bail};
use log::info;

use crate::{config::Config, reader::ReaderBuf};

/// Check if the provided buffer looks like an HTTP request. This does not guarantee the request is
/// a genuine one, but should be enough to at least try handling it.
pub(crate) fn is_http<R: Read>(rb: &ReaderBuf<R>) -> bool {
    // The buffer comes from previous reads, we might have failed to read up to 5 bytes. No reason
    // try try reading it again. In all other cases 5 bytes is the maximal length we can match all
    // HTTP methods on. This is a shortcut but as we don't try to be 100% correct here, this is
    // fine.
    let buf = rb.buf();
    if buf.len() >= 5 {
        // From https://developer.mozilla.org/fr/docs/Web/HTTP/Methods
        if let Ok(
            "GET /" | "HEAD " | "POST " | "PUT /" | "DELET" | "CONNE" | "OPTIO" | "TRACE" | "PATCH",
        ) = str::from_utf8(&buf[..5])
        {
            return true;
        }
    }
    false
}

/// Redirect an HTTP request with a 308.
pub(crate) fn try_redirect<R: Read + Write>(
    config: &Config,
    client: &SocketAddr,
    rb: &mut ReaderBuf<R>,
) -> Result<()> {
    let host = match get_host(rb)? {
        Some(host) => host,
        None => return Ok(()), // Not much we can do, not really an error.
    };
    #[cfg(not(test))]
    crate::context::set_hostname(host)?;

    match config.get_route(host) {
        Some(route) => {
            if !route.http_redirect {
                bail!("Denied HTTP redirect to HTTPS (disabled)");
            }

            if !route.is_allowed(client) {
                bail!("Denied HTTP redirect to HTTPS (ACLs)");
            }
        }
        None => bail!("Unknown hostname ({host})"), // Not much we can do, not really an error.
    }

    info!("Redirecting HTTP request to HTTPS");
    let response = format!(
        "HTTP/1.0 308 Unknown\r\nLocation: https://{host}:{}\r\n\r\n",
        config.bind_https.port()
    );
    Ok(rb.get_mut().write_all(response.as_bytes())?)
}

/// Try parsing an HTTP request host.
fn get_host<R: Read>(rb: &mut ReaderBuf<R>) -> Result<Option<&str>> {
    // Try to read the remaining of the HTTP headers. 8KB is the limit size on
    // many web servers.
    rb.read(8192)?;
    let headers = str::from_utf8(rb.buf())?;

    // Skip the request line and loop over the HTTP headers to find the Host
    // one and extract its value.
    for hdr in headers.split("\r\n").skip(1) {
        match hdr.split_once(':') {
            Some(("Host", val)) => {
                let val = val.trim();
                // Host could be in the <host>:<port> form.
                return Ok(Some(match val.split_once(':') {
                    Some((host, _)) => host,
                    _ => val,
                }));
            }
            _ => continue,
        }
    }

    info!("Could not find HTTP Host header in request");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{config::Config, reader::ReaderBuf as B, tls::tests::RECORD_SNI_ALPN};

    #[test]
    fn is_http() {
        let valid: &[&str] = &[
            "GET /", "HEAD ", "POST ", "PUT /", "DELET", "CONNE", "OPTIO", "TRACE", "PATCH",
        ];
        for s in valid.iter() {
            let mut rb = &mut B::from_bytes(s.as_bytes());
            rb.read(5).unwrap();
            assert!(super::is_http(&mut rb));
        }

        let mut rb = B::from_bytes(&[]);
        rb.read(5).unwrap();
        assert_eq!(super::is_http(&mut rb), false);

        let mut rb = B::from_bytes(&[0; 256]);
        rb.read(5).unwrap();
        assert_eq!(super::is_http(&mut rb), false);
    }

    #[test]
    fn get_host() {
        assert_eq!(super::get_host(&mut B::from_bytes(&[])).unwrap(), None);
        assert_eq!(super::get_host(&mut B::from_bytes(b"GET /")).unwrap(), None);
        assert_eq!(
            super::get_host(&mut B::from_bytes(b"GET /\r\nHost: example.net\r\n")).unwrap(),
            Some("example.net")
        );
        assert_eq!(
            super::get_host(&mut B::from_bytes(
                b"GET /\r\nHost: foo.example.net:8080\r\n"
            ))
            .unwrap(),
            Some("foo.example.net")
        );
        assert_eq!(
            super::get_host(&mut B::from_bytes(
                b"GET /\r\nScheme: https\r\nHost: example.net\r\nFilename: foo\r\n"
            ))
            .unwrap(),
            Some("example.net")
        );

        // Invalid UTF-8 sequence.
        assert!(super::get_host(&mut B::from_bytes(RECORD_SNI_ALPN)).is_err());
    }

    #[test]
    fn try_redirect() {
        let config = Config::from_str(
            "
routes:
  - domains:
    - example.net
    backend:
      address: 127.0.0.1:8000
  - domains:
    - denied.example.net
    http_redirect: false
    backend:
      address: 127.0.0.1:8000
  - domains:
    - acls.example.net
    backend:
      address: 127.0.0.1:8000
    allowed_ranges:
    - 10.0.0.0/8
    denied_ranges:
    - 127.0.0.0/24
        ",
        )
        .unwrap();

        let req = "GET /\r\nHost: example.net\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(super::try_redirect(&config, &"127.0.0.1:10000".parse().unwrap(), &mut rb).is_ok());

        let buf = rb.into_inner().into_inner();
        assert_eq!(
            &buf[req.len()..],
            b"HTTP/1.0 308 Unknown\r\nLocation: https://example.net:443\r\n\r\n"
        );

        let req = "GET /\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(super::try_redirect(&config, &"127.0.0.1:10000".parse().unwrap(), &mut rb).is_ok());

        let req = "GET /\r\nHost: denied.example.net\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(
            super::try_redirect(&config, &"127.0.0.1:10000".parse().unwrap(), &mut rb).is_err()
        );

        let req = "GET /\r\nHost: foo.example.net\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(
            super::try_redirect(&config, &"127.0.0.1:10000".parse().unwrap(), &mut rb).is_err()
        );

        let req = "GET /\r\nHost: acls.example.net\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(
            super::try_redirect(&config, &"127.0.0.1:10000".parse().unwrap(), &mut rb).is_err()
        );

        let req = "GET /\r\nHost: acls.example.net\r\n".as_bytes();
        let mut rb = B::new(Cursor::new(req.to_vec()));
        assert!(super::try_redirect(&config, &"10.0.42.1:10000".parse().unwrap(), &mut rb).is_ok());
    }
}
