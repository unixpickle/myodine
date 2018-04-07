use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

/// Create a UDP socket and connect to an address.
///
/// The address should parse into an "IP:port" pair.
pub fn dial_udp(addr: &str) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(OutgoingAddrRange{})?;
    let remote = addr.parse::<SocketAddr>()
        .map_err(|x| io::Error::new(ErrorKind::ConnectionRefused, x))?;
    sock.connect(remote)?;
    Ok(sock)
}

struct OutgoingAddrRange;

impl ToSocketAddrs for OutgoingAddrRange {
    type Iter = <Vec<SocketAddr> as IntoIterator>::IntoIter;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        let mut result = Vec::new();
        result.extend((Ipv4Addr::new(0, 0, 0, 0), 0u16).to_socket_addrs()?);
        result.extend((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0u16).to_socket_addrs()?);
        Ok(result.into_iter())
    }
}
