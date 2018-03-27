use std::io;
use std::net::UdpSocket;
use std::num::Wrapping;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread::spawn;
use std::time::{Duration, Instant};

use conn::dial::dial_udp;
use dns_coding::{dns_decode, dns_encode};
use dns_proto::Message;

pub enum Event {
    Response(usize, Message),
    Timeout(usize),
    SendError(usize, String),
    ConnectError(usize, io::Error),
    SocketError(usize, io::Error)
}

pub struct Highway {
    senders: Vec<Sender<(Message, Duration)>>
}

impl Highway {
    pub fn open(remote_addr: &str, lanes: usize) -> (Highway, Receiver<Event>) {
        let (event_sender, event_receiver) = channel();
        let mut senders = Vec::new();
        for i in 0..lanes {
            let lane = i;
            let addr_copy = String::from(remote_addr);
            let (sender, receiver) = channel();
            senders.push(sender);
            let local_sender = event_sender.clone();
            spawn(move || {
                Highway::run_lane(lane, receiver, addr_copy, local_sender.clone());
            });
        }
        (Highway{senders: senders}, event_receiver)
    }

    pub fn send(&self, lane: usize, message: Message, timeout: Duration) {
        self.senders[lane].send((message, timeout)).ok();
    }

    fn run_lane(
        lane: usize,
        receiver: Receiver<(Message, Duration)>,
        addr: String,
        event_sender: Sender<Event>
    ) {
        match dial_udp(&addr) {
            Ok(socket) => {
                HighwayLane{
                    lane: lane,
                    seq_number: (Wrapping(lane as u16) * Wrapping(10)).0,
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

struct HighwayLane {
    lane: usize,
    seq_number: u16,
    sender: Sender<Event>,
    socket: UdpSocket
}

impl HighwayLane {
    fn run_loop(&mut self, receiver: Receiver<(Message, Duration)>) {
        for (mut message, timeout) in receiver {
            let send_res = if let Err(err) = self.send_message(message) {
                self.send_event(Event::SendError(self.lane, err))
            } else {
                match self.recv_response(timeout) {
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

    fn recv_response(&self, timeout: Duration) -> io::Result<Option<Message>> {
        let start = Instant::now();
        loop {
            let elapsed = Instant::now().duration_since(start);
            if elapsed >= timeout {
                return Ok(None);
            }
            self.socket.set_read_timeout(Some(timeout - elapsed))?;
            let mut buffer = [0u8; 2048];
            if let Ok(size) = self.socket.recv(&mut buffer) {
                if let Ok(response) = dns_decode::<Message>(buffer[..size].to_vec()) {
                    if response.header.identifier == self.seq_number {
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
