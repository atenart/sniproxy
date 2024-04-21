use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
};

use anyhow::{bail, Result};

/// Writes a `version` HAProxy protocol header.
pub(crate) fn write_header<W>(
    w: W,
    version: u8,
    local: &SocketAddr,
    peer: &SocketAddr,
) -> Result<()>
where
    W: Write,
{
    match version {
        1 => write_header_v1(w, local, peer),
        2 => write_header_v2(w, local, peer),
        x => bail!("Invalid HAProxy protocol header version ({x})"),
    }
}

/// Write an HAProxy protocol header version 1 in a writer.
/// See https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
fn write_header_v1<W>(mut w: W, local: &SocketAddr, peer: &SocketAddr) -> Result<()>
where
    W: Write,
{
    Ok(write!(
        w,
        "PROXY {} {} {} {} {}\r\n",
        match (local, peer) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
            (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
            _ => bail!("Invalid address types (mixing IPv4 and IPv6)"),
        },
        peer.ip(),
        local.ip(),
        peer.port(),
        local.port()
    )?)
}

/// Write an HAProxy protocol header version 2 in a writer.
/// See https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
fn write_header_v2<W>(mut w: W, local: &SocketAddr, peer: &SocketAddr) -> Result<()>
where
    W: Write,
{
    // Protocol signature and the command (\x2 followed by \x0 for 'local' or
    // \x1 for 'proxy').
    w.write_all(&[
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21,
    ])?;

    // Transport protocol and address family. The highest 4 bits represent
    // the address family (\x1: AF_INET, \x2: AF_INET6) and the lowest 4
    // bits the protocol (\x1: SOCK_STREAM).
    //
    // Followed by the address length. 12 for IPv4 and 36 for IPv6.
    match (local, peer) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => {
            w.write_all(&[0x11])?;
            w.write_all(&u16::to_be_bytes(12))?;
        }
        (SocketAddr::V6(_), SocketAddr::V6(_)) => {
            w.write_all(&[0x21])?;
            w.write_all(&u16::to_be_bytes(36))?;
        }
        _ => bail!("Invalid address types (mixing IPv4 and IPv6)"),
    }

    // Now write addresses & ports information.
    match peer.ip() {
        IpAddr::V4(addr) => w.write_all(&addr.octets())?,
        IpAddr::V6(addr) => w.write_all(&addr.octets())?,
    }
    match local.ip() {
        IpAddr::V4(addr) => w.write_all(&addr.octets())?,
        IpAddr::V6(addr) => w.write_all(&addr.octets())?,
    }
    w.write_all(&u16::to_be_bytes(peer.port()))?;
    w.write_all(&u16::to_be_bytes(local.port()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str;

    #[test]
    fn header_v1() {
        let local = "172.16.99.1:443".parse().unwrap();
        let peer = "10.0.42.132:1337".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v1(&mut w, &local, &peer).is_ok());
        assert_eq!(
            str::from_utf8(&w).unwrap(),
            "PROXY TCP4 10.0.42.132 172.16.99.1 1337 443\r\n"
        );

        let local = "[1111:1::42]:10443".parse().unwrap();
        let peer = "[1337:42::700]:12345".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v1(&mut w, &local, &peer).is_ok());
        assert_eq!(
            str::from_utf8(&w).unwrap(),
            "PROXY TCP6 1337:42::700 1111:1::42 12345 10443\r\n"
        );

        let local = "172.16.99.1:443".parse().unwrap();
        let peer = "[1337:42::700]:12345".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v1(&mut w, &local, &peer).is_err());

        let local = "[1111:1::42]:10443".parse().unwrap();
        let peer = "10.0.42.132:1337".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v1(&mut w, &local, &peer).is_err());
    }

    #[test]
    fn header_v2() {
        let local = "172.16.99.1:443".parse().unwrap();
        let peer = "10.0.42.132:1337".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v2(&mut w, &local, &peer).is_ok());
        assert_eq!(
            &w,
            &[
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
                0x00, 0x0c, 0x0a, 0x00, 0x2a, 0x84, 0xac, 0x10, 0x63, 0x01, 0x05, 0x39, 0x01, 0xbb
            ]
        );

        let local = "[1111:1::42]:10443".parse().unwrap();
        let peer = "[1337:42::700]:12345".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v2(&mut w, &local, &peer).is_ok());
        assert_eq!(
            &w,
            &[
                0xd, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x21,
                0x00, 0x24, 0x13, 0x37, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x07, 0x00, 0x11, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x30, 0x39, 0x28, 0xcb,
            ]
        );

        let local = "172.16.99.1:443".parse().unwrap();
        let peer = "[1337:42::700]:12345".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v2(&mut w, &local, &peer).is_err());

        let local = "[1111:1::42]:10443".parse().unwrap();
        let peer = "10.0.42.132:1337".parse().unwrap();
        let mut w = Vec::new();
        assert!(super::write_header_v2(&mut w, &local, &peer).is_err());
    }
}
