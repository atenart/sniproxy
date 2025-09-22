use std::{
    hint::unreachable_unchecked,
    io::{BufWriter, Write},
    net::{SocketAddr, SocketAddrV4, TcpStream},
    os::fd::{FromRawFd, IntoRawFd},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use log::{debug, info, trace};

use crate::{
    config::{self, Config, Nat46Address},
    context, http, proxy_protocol,
    reader::ReaderBuf,
    tcp::socket::Socket6,
    tls::{self, Tls},
};

/// Handle TCP/TLS connections.
pub(crate) async fn handle_stream(config: Arc<Config>, stream: TcpStream) -> Result<()> {
    let mut rb = ReaderBuf::with_capacity(tls::RECORD_MAX_LEN, stream);

    // Start by checking we got a valid TLS message, and if true parse it.
    let tls = match Tls::from(&mut rb) {
        Ok(tls) => tls,
        Err(e) => {
            // If this looks like an HTTP request, try to redirect it.
            // Luckily http::is_http needs 5 bytes in the buffer and the
            // minimal TLS parsing reads 5 bytes.
            if http::is_http(&rb) {
                return http::try_redirect(&config, &context::peer_addr()?, &mut rb);
            }

            tls::alert(rb.get_mut(), tls::AlertDescription::InternalError)?;
            bail!("Could not parse TLS message: {e}");
        }
    };

    // Retrieve the SNI hostname.
    let hostname = match tls.hostname() {
        Some(name) => name,
        // None was present, which is valid. But we can't do anything with that message.
        None => {
            tls::alert(rb.get_mut(), tls::AlertDescription::UnrecognizedName)?;
            info!("No SNI hostname in message");
            return Ok(());
        }
    };
    debug!("Found SNI {hostname} in TLS handshake");
    context::set_hostname(hostname)?;

    let peer = &context::peer_addr()?;
    let backend = config
        .get_backend(hostname, peer, tls.is_challenge())
        .or_else(|e| match e.downcast() {
            Ok(e) => match e {
                config::Error::HostnameNotFound => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::UnrecognizedName)?;
                    bail!("No route found for '{hostname}'")
                }
                config::Error::NoBackend => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::AccessDenied)?;
                    bail!("No backend defined for '{hostname}'")
                }
                config::Error::AccessDenied => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::AccessDenied)?;
                    bail!("Request from {peer} for '{hostname}' was denied by ACLs")
                }
            },
            Err(e) => bail!(e),
        })?;
    debug!(
        "Using backend {:?} (is alpn challenge? {})",
        backend.to_socket_addr(),
        tls.is_challenge(),
    );

    // Connect to the backend.
    let conn = match tcp_connect_timeout(
        &backend.to_socket_addr()?,
        Duration::from_secs(3),
        &backend.nat46_prefix,
        rb.get_ref().peer_addr()?,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            tls::alert(rb.get_mut(), tls::AlertDescription::InternalError)?;
            bail!("Could not connect to backend '{}': {e}", &backend.address);
        }
    };

    // Use a buffered writer to avoid small writes until we start forwarding the
    // data.
    let mut bw = BufWriter::new(conn);

    // Send an HAProxy protocol header if needed.
    if let Some(version) = backend.proxy_protocol {
        proxy_protocol::write_header(&mut bw, version, &context::local_addr()?, peer)?;
    }

    // Replay the handshake.
    bw.write_all(rb.buf())?;

    // We can now flush the buffered writer and stop using it to avoid adding
    // buffering in the middle of the connection.
    let mut conn = bw.into_inner()?;

    // Do not use read & write timeouts for proxying.
    if let Err(e) = conn.set_read_timeout(None) {
        tls::alert(&mut conn, tls::AlertDescription::InternalError)?;
        bail!("Could not unset the read timeout on TCP stream: {e}");
    }
    if let Err(e) = conn.set_write_timeout(None) {
        tls::alert(&mut conn, tls::AlertDescription::InternalError)?;
        bail!("Could not unset the write timeout on TCP stream: {e}");
    }

    super::tcp::proxy(rb.into_inner(), conn).await?;
    Ok(())
}

fn tcp_connect_timeout(
    addr: &SocketAddr,
    timeout: std::time::Duration,
    nat46_prefix: &Option<Nat46Address>,
    peer_addr: SocketAddr,
) -> std::io::Result<TcpStream> {
    // Guard check for unsuported freebind configuration. Fallback to std
    if !addr.is_ipv6() || nat46_prefix.is_none() {
        trace!("Not doing nat46");
        return TcpStream::connect_timeout(addr, timeout);
    }

    // SAFETY: checked above to be non null
    let nat46_prefix = unsafe { nat46_prefix.as_ref().unwrap_unchecked() };
    // SAFETY: checked above to be V4
    let peer_addr = match peer_addr {
        SocketAddr::V4(v) => v,
        SocketAddr::V6(v) if matches!(v.ip().to_ipv4_mapped(), Some(_ip)) => {
            let ip = unsafe { v.ip().to_ipv4_mapped().unwrap_unchecked() };
            SocketAddrV4::new(ip, v.port())
        }
        _ => {
            trace!("Not doing nat46");
            return TcpStream::connect_timeout(addr, timeout);
        }
    };
    // SAFETY: checked above to be V6
    let addr = match addr {
        SocketAddr::V6(v) => v,
        _ => unsafe { unreachable_unchecked() },
    };

    let nat_addr = nat46_prefix.to_sockaddr_in6_natted(&peer_addr);

    let mut socket = Socket6::new()?;
    socket.setsockopt(libc::SOL_IPV6, libc::IPV6_FREEBIND, 1u32)?;
    socket.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1u32)?;

    socket.bind(nat_addr)?;

    socket.connect_timeout(addr, timeout)?;

    Ok(unsafe { TcpStream::from_raw_fd(socket.into_raw_fd()) })
}
