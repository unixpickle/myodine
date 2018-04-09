use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::num::Wrapping;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::{Sender, Receiver, TryRecvError, channel};
use std::thread::spawn;
use std::time::{Duration, Instant};

use dns_coding::{dns_decode, dns_encode};
use dns_proto::Message;

use super::highway::{Event, Highway};
use super::dial_tcp;

/// A highway that multiplexes queries over one TCP socket.
pub struct TCPHighway {
    sender: Sender<(usize, Message)>,
    lanes: usize,

    // Used for side-effects of Drop.
    #[allow(dead_code)]
    kill_sender: Sender<()>
}

impl Highway for TCPHighway {
    fn num_lanes(&self) -> usize {
        self.lanes
    }

    fn send(&self, lane: usize, message: Message) {
        self.sender.send((lane, message)).ok();
    }
}

impl TCPHighway {
    /// Create a new Highway and connect it to a remote address.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - An "IP:port" pair.
    /// * `lanes` - The number of virtual lanes.
    /// * `sweep_time` - the interval at which requests are checked for timeouts.
    /// * `max_time` - a soft upper bound on the time for a query to last.
    ///
    /// Returns the new TCPHighway and its corresponding event queue.
    pub fn open(
        remote_addr: &str,
        lanes: usize,
        sweep_time: Duration,
        max_time: Duration
    ) -> (TCPHighway, Receiver<Event>) {
        let (event_sender, event_receiver) = channel();
        let (msg_sender, msg_receiver) = channel();
        let (kill_sender, kill_receiver) = channel();
        let addr_copy = String::from(remote_addr); // TODO: to_owned here?
        spawn(move || {
            TCPHighway::run_highway(sweep_time, max_time, msg_receiver, addr_copy, event_sender,
                kill_receiver);
        });
        (TCPHighway{
            sender: msg_sender,
            lanes: lanes,
            kill_sender: kill_sender
        }, event_receiver)
    }

    fn run_highway(
        sweep_time: Duration,
        max_time: Duration,
        receiver: Receiver<(usize, Message)>,
        addr: String,
        event_sender: Sender<Event>,
        kill_receiver: Receiver<()>
    ) {
        match dial_tcp(&addr) {
            Ok(socket) => {
                let pending = PendingQueue::new();
                let pending_1 = pending.clone();
                let socket_1 = socket.try_clone().unwrap(); // TODO: handle error.
                let sender_1 = event_sender.clone();
                spawn(move || {
                    write_loop(socket_1, pending_1, sender_1, receiver, max_time);
                });
                let read_res = read_loop(socket, pending, &event_sender, sweep_time,
                    kill_receiver);
                if let Err(err) = read_res {
                    event_sender.send(Event::ConnectError(0, err)).ok();
                }
            },
            Err(err) => {
                event_sender.send(Event::ConnectError(0, err)).ok();
            }
        }
    }
}

// TODO: no mut arguments here. Use &mut.
fn write_loop(
    mut socket: TcpStream,
    mut pending: PendingQueue,
    sender: Sender<Event>,
    receiver: Receiver<(usize, Message)>,
    max_time: Duration
) {
    let mut cur_seq: Wrapping<u16> = Wrapping(1337);
    for (lane, mut msg) in receiver {
        msg.header.identifier = cur_seq.0;
        cur_seq = cur_seq + Wrapping(1);
        // TODO: look into using encode_with_length here.
        match dns_encode(&msg) {
            Ok(data) => {
                let mut data_1 = dns_encode(&(data.len() as u16)).unwrap();
                data_1.extend(data);
                // TODO: look for built-in function for this.
                if let Err(err) = write_data(&mut socket, &data_1) {
                    let msg = format!("failed to write to socket: {}", err);
                    sender.send(Event::SendError(lane, msg)).ok();
                } else {
                    pending.add(msg, lane, max_time.clone());
                }
            },
            Err(err) => {
                sender.send(Event::SendError(lane, err)).ok();
            }
        }
    }
}

// TODO: no mut arguments here. Use &mut.
fn read_loop(
    mut socket: TcpStream,
    mut pending: PendingQueue,
    sender: &Sender<Event>,
    sweep_time: Duration,
    kill_receiver: Receiver<()>
) -> Result<(), io::Error> {
    socket.set_read_timeout(Some(sweep_time))?;
    let mut reader = MessageReader::new();
    loop {
        for msg in reader.read_chunk(&mut socket)? {
            if let Some(pending) = pending.remove(msg.header.identifier) {
                if let Err(_) = sender.send(Event::Response(pending.lane, msg)) {
                    return Ok(());
                }
            }
        }
        for timed_out in pending.remove_timeouts() {
            if let Err(_) = sender.send(Event::Timeout(timed_out.lane)) {
                return Ok(());
            }
        }
        match kill_receiver.try_recv() {
            Err(TryRecvError::Disconnected) => return Ok(()),
            _ => ()
        }
    }
}

fn write_data(socket: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        written += socket.write(&data[written..data.len()])?;
    }
    Ok(())
}

struct PendingMessage {
    id: u16,
    lane: usize,
    start_time: Instant,
    timeout: Duration
}

#[derive(Clone)]
struct PendingQueue {
    queue: Arc<RwLock<Vec<PendingMessage>>>
}

impl PendingQueue {
    fn new() -> PendingQueue {
        PendingQueue{queue: Arc::new(RwLock::new(Vec::new()))}
    }

    fn add(&mut self, msg: Message, lane: usize, timeout: Duration) {
        let list: &mut Vec<PendingMessage> = &mut self.queue.write().unwrap();
        list.push(PendingMessage{
            id: msg.header.identifier,
            lane: lane,
            start_time: Instant::now(),
            timeout: timeout
        });
    }

    fn remove_timeouts(&mut self) -> Vec<PendingMessage> {
        let mut removed = Vec::new();
        let list: &mut Vec<PendingMessage> = &mut self.queue.write().unwrap();
        for i in (0..list.len()).into_iter().rev() {
            if list[i].start_time.elapsed() > list[i].timeout {
                removed.push(list.remove(i));
            }
        }
        removed
    }

    fn remove(&mut self, id: u16) -> Option<PendingMessage> {
        let list: &mut Vec<PendingMessage> = &mut self.queue.write().unwrap();
        for i in 0..list.len() {
            if list[i].id == id {
                return Some(list.remove(i));
            }
        }
        None
    }
}

struct MessageReader {
    buffer: Vec<u8>
}

impl MessageReader {
    fn new() -> MessageReader {
        MessageReader{buffer: Vec::new()}
    }

    fn read_chunk(&mut self, socket: &mut TcpStream) -> Result<Vec<Message>, io::Error> {
        let mut buffer = [0u8; 2048];
        match socket.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    // TODO: return EOF error here.
                    return Ok(Vec::new());
                }
                self.buffer.extend(buffer[..size].iter());
                self.pop_all()
            }
            Err(_) => {
                // TODO: handle timeout properly
                Ok(Vec::new())
            }
        }
    }

    fn pop_all(&mut self) -> Result<Vec<Message>, io::Error> {
        let mut res = Vec::new();
        loop {
            match self.pop_message() {
                None => return Ok(res),
                Some(x) => {
                    if let Ok(msg) = dns_decode(x) {
                        res.push(msg);
                    }
                }
            }
        }
    }

    fn pop_message(&mut self) -> Option<Vec<u8>> {
        if self.buffer.len() < 2 {
            return None;
        }
        let msg_size = (((self.buffer[0] as u16) << 8) | (self.buffer[1] as u16)) as usize;
        // TODO: does size include 2 byte size field?
        if self.buffer.len() >= msg_size + 2 {
            let data = self.buffer[2..(2 + msg_size)].to_vec();
            // TODO: more efficient way to slice up data?
            self.buffer = self.buffer[(2 + msg_size)..self.buffer.len()].to_vec();
            Some(data)
        } else {
            None
        }
    }
}
