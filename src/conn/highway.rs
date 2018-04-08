use std::io;

use dns_proto::Message;

use super::dial_udp;

/// An event from a `Highway`.
#[derive(Debug)]
pub enum Event {
    Response(usize, Message),
    Timeout(usize),
    SendError(usize, String),
    ConnectError(usize, io::Error),
    SocketError(usize, io::Error)
}

/// A batched DNS requester.
pub trait Highway {
    /// Get the number of virtual connections.
    fn num_lanes(&self) -> usize;

    /// Send a DNS message to the virtual connection.
    ///
    /// # Arguments
    ///
    /// * `lane`: The connection to use. This lane should not be busy.
    /// * `message`: The message to send on the lane.
    fn send(&self, lane: usize, message: Message);
}
