use std::io;
use std::net::{SocketAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread::spawn;
use std::time::{Duration, Instant};

use myodine::dns_coding::{dns_decode, dns_encode};
use myodine::dns_proto::message::Message;

use events::Event;

pub struct Requester {
    senders: Vec<Sender<(Message, Duration)>>
}

impl Requester {
    pub fn open(remote_addr: &str, num_socks: usize, event_sender: Sender<Event>) -> Requester {
        let mut senders = Vec::new();
        for i in 0..num_socks {
            let thread_idx = i;
            let thread_events = event_sender.clone();
            let thread_remote = String::from(remote_addr);
            let (sender, receiver) = channel();
            senders.push(sender);
            spawn(move || {
                let thread_res = Requester::background_thread(thread_idx, receiver, thread_remote,
                    thread_events.clone());
                if let Err(err) = thread_res {
                    thread_events.send(Event::Error(err)).ok();
                }
            });
        }
        Requester{senders: senders}
    }

    pub fn send(&self, sock_idx: usize, message: Message, timeout: Duration) {
        self.senders[sock_idx].send((message, timeout)).ok();
    }

    fn background_thread(idx: usize, receiver: Receiver<(Message, Duration)>, addr: String,
        event_sender: Sender<Event>) -> Result<(), String>
    {
        match UdpSocket::bind(OutgoingAddrRange{}) {
            Ok(socket) => {
                let remote = addr.parse::<SocketAddr>().map_err(|x| format!("connect: {}", x))?;
                match socket.connect(remote) {
                    Ok(_) => {
                        Requester::background_loop(idx, receiver, socket, event_sender)
                    }
                    Err(err) => Err(format!("connect socket: {}", err))
                }
            },
            Err(err) => Err(format!("open socket: {}", err))
        }
    }

    fn background_loop(idx: usize, receiver: Receiver<(Message, Duration)>, socket: UdpSocket,
        event_sender: Sender<Event>) -> Result<(), String>
    {
        macro_rules! try_send {
            ($x:expr) => {
                {
                    if let Err(_) = event_sender.send($x) {
                        return Ok(());
                    }
                }
            }
        }
        let mut seq_number = (idx * 10) as u16;
        for (mut message, timeout) in receiver {
            seq_number += 1;
            message.header.identifier = seq_number;
            if let Err(err) = socket.send(&dns_encode(&message)?) {
                return Err(format!("error sending packet: {}", err));
            }
            let start = Instant::now();
            loop {
                let elapsed = Instant::now().duration_since(start);
                if elapsed >= timeout {
                    try_send!(Event::ReadTimeout(idx));
                    break;
                }
                socket.set_read_timeout(Some(timeout - elapsed)).map_err(|x| format!("{}", x))?;
                let mut buffer = [0u8; 2048];
                if let Ok(size) = socket.recv(&mut buffer) {
                    if let Ok(response) = dns_decode::<Message>(buffer[..size].to_vec()) {
                        if response.header.identifier == seq_number {
                            try_send!(Event::Response(idx, response));
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

struct OutgoingAddrRange;

impl ToSocketAddrs for OutgoingAddrRange {
    type Iter = <Vec<SocketAddr> as IntoIterator>::IntoIter;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        let mut result = Vec::new();
        for port in 10000u16..65535u16 {
            result.extend((Ipv4Addr::new(0, 0, 0, 0), port).to_socket_addrs()?);
        }
        Ok(result.into_iter())
    }
}
