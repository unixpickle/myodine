use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};

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
        // TODO: see if we can simply use a port of 0.
        for port in 10000u16..65535u16 {
            // TODO: do IPv6 as well!
            result.extend((Ipv4Addr::new(0, 0, 0, 0), port).to_socket_addrs()?);
        }
        Ok(result.into_iter())
    }
}
