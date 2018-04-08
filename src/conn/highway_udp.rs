use std::io;
use std::net::UdpSocket;
use std::num::Wrapping;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

use dns_coding::{dns_decode, dns_encode};
use dns_proto::Message;

use super::highway::{Event, Highway};
use super::dial_udp;

/// A highway that opens one UDP socket per lane.
pub struct UDPHighway {
    min_time: Duration,
    max_time: Duration,
    senders: Vec<Sender<(Message, Duration, Duration)>>
}

impl Highway for UDPHighway {
    fn num_lanes(&self) -> usize {
        self.senders.len()
    }

    fn send(&self, lane: usize, message: Message) {
        self.senders[lane].send((message, self.min_time.clone(), self.max_time.clone())).ok();
    }
}

impl UDPHighway {
    /// Create a new Highway and connect it to a remote address.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - An "IP:port" pair.
    /// * `lanes` - The number of UDP connections.
    /// * `min_time` - the minimum time for a query to last.
    /// * `max_time` - a soft upper bound on the time for a query to last.
    ///
    /// Returns the new UDPHighway and its corresponding event queue.
    pub fn open(
        remote_addr: &str,
        lanes: usize,
        min_time: Duration,
        max_time: Duration
    ) -> (UDPHighway, Receiver<Event>) {
        let (event_sender, event_receiver) = channel();
        let mut senders = Vec::new();
        for i in 0..lanes {
            let lane = i;
            let addr_copy = remote_addr.to_owned();
            let (sender, receiver) = channel();
            senders.push(sender);
            let local_sender = event_sender.clone();
            spawn(move || {
                UDPHighway::run_lane(lane, receiver, addr_copy, local_sender.clone());
            });
        }
        (UDPHighway{
            min_time: min_time,
            max_time: max_time,
            senders: senders
        }, event_receiver)
    }

    fn run_lane(
        lane: usize,
        receiver: Receiver<(Message, Duration, Duration)>,
        addr: String,
        event_sender: Sender<Event>
    ) {
        match dial_udp(&addr) {
            Ok(socket) => {
                UDPHighwayLane{
                    lane: lane,
                    seq_number: (Wrapping(lane as u16) * Wrapping(1337)).0,
                    sender: event_sender,
                    socket: socket
                }.run_loop(receiver);
            },
            Err(err) => {
                event_sender.send(Event::ConnectError(lane, err)).ok();
            }
        }
    }
}

struct UDPHighwayLane {
    lane: usize,
    seq_number: u16,
    sender: Sender<Event>,
    socket: UdpSocket
}

impl UDPHighwayLane {
    fn run_loop(&mut self, receiver: Receiver<(Message, Duration, Duration)>) {
        for (mut message, min_time, max_time) in receiver {
            let send_res = if let Err(err) = self.send_message(message) {
                self.send_event(Event::SendError(self.lane, err))
            } else {
                match self.recv_response(min_time, max_time) {
                    Ok(None) => self.send_event(Event::Timeout(self.lane)),
                    Ok(Some(m)) => self.send_event(Event::Response(self.lane, m)),
                    Err(err) => self.send_event(Event::SocketError(self.lane, err))
                }
            };
            if !send_res {
                return;
            }
        }
    }

    fn send_message(&mut self, mut message: Message) -> Result<(), String> {
        message.header.identifier = self.next_seq();
        if let Err(err) = self.socket.send(&dns_encode(&message)?) {
            Err(format!("error sending datagram: {}", err))
        } else {
            Ok(())
        }
    }

    fn recv_response(
        &self,
        min_time: Duration,
        max_time: Duration
    ) -> io::Result<Option<Message>> {
        let start = Instant::now();
        loop {
            let elapsed = Instant::now().duration_since(start);
            if elapsed >= max_time {
                return Ok(None);
            }
            self.socket.set_read_timeout(Some(max_time - elapsed))?;
            let mut buffer = [0u8; 2048];
            if let Ok(size) = self.socket.recv(&mut buffer) {
                if let Ok(response) = dns_decode::<Message>(buffer[..size].to_vec()) {
                    if response.header.identifier == self.seq_number {
                        let passed = Instant::now().duration_since(start);
                        if passed < min_time {
                            sleep(min_time - passed);
                        }
                        return Ok(Some(response));
                    }
                }
            }
        }
    }

    fn next_seq(&mut self) -> u16 {
        self.seq_number = (Wrapping(self.seq_number) + Wrapping(1)).0;
        self.seq_number
    }

    fn send_event(&self, event: Event) -> bool {
        self.sender.send(event).is_ok()
    }
}
