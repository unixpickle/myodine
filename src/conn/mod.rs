//! APIs for managing UDP and DNS connections.

mod chunker;
mod dial;
mod highway;
mod highway_tcp;
mod highway_udp;

pub use self::chunker::TcpChunker;
pub use self::dial::{dial_tcp, dial_udp};
pub use self::highway::{Event, Highway};
pub use self::highway_tcp::TCPHighway;
pub use self::highway_udp::UDPHighway;
