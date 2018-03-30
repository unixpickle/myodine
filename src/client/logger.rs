use chrono::Local;

use std::fmt::{Display, Error, Formatter};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RawLogger {
    sender: Sender<String>
}

impl RawLogger {
    pub fn new() -> RawLogger {
        let (sender, receiver) = channel();
        spawn(|| {
            for msg in receiver {
                println!("{} {}", Local::now().to_rfc3339(), msg);
            }
        });
        RawLogger{sender: sender}
    }

    pub fn log(&self, msg: String) {
        self.sender.send(msg).unwrap();
    }
}

pub struct SessionLogger {
    sender: Sender<SessionMessage>,

    // Used for side-effects of Drop.
    #[allow(dead_code)]
    timeout_closer: Sender<()>
}

impl SessionLogger {
    pub fn new(raw: RawLogger) -> SessionLogger {
        let (sender, receiver) = channel();
        spawn(|| {
            SessionLogger::log_loop(raw, receiver);
        });
        let local_sender = sender.clone();
        let (timeout_closer, close_receiver) = channel();
        spawn(|| {
            SessionLogger::interval_loop(local_sender, close_receiver);
        });
        SessionLogger{
            sender: sender,
            timeout_closer: timeout_closer
        }
    }

    pub fn log_timeout(&self) {
        self.sender.send(SessionMessage::Timeout).unwrap();
    }

    pub fn log_response(&self) {
        self.sender.send(SessionMessage::Response).unwrap();
    }

    pub fn log_inbound(&self, size: usize) {
        self.sender.send(SessionMessage::Inbound(size)).unwrap();
    }

    pub fn log_outbound(&self, size: usize) {
        self.sender.send(SessionMessage::Outbound(size)).unwrap();
    }

    pub fn log_raw(&self, msg: String) {
        self.sender.send(SessionMessage::Raw(msg)).unwrap();
    }

    fn log_loop(raw: RawLogger, receiver: Receiver<SessionMessage>) {
        let mut stats = SessionStats::new();
        for msg in receiver {
            match msg {
                SessionMessage::Raw(x) => {
                    raw.log(x);
                },
                SessionMessage::Flush => {
                    raw.log(format!("{}", stats));
                    stats = SessionStats::new();
                },
                _ => {
                    stats.update(msg);
                }
            }
        }
    }

    fn interval_loop(sender: Sender<SessionMessage>, closer: Receiver<()>) {
        loop {
            sleep(Duration::from_secs(10));
            match closer.try_recv() {
                Err(TryRecvError::Disconnected) => return,
                _ => ()
            }
            if sender.send(SessionMessage::Flush).is_err() {
                return;
            }
        }
    }
}

enum SessionMessage {
    Flush,
    Timeout,
    Response,
    Inbound(usize),
    Outbound(usize),
    Raw(String)
}

struct SessionStats {
    start_time: Instant,
    total_timeouts: usize,
    total_responses: usize,
    total_inbound: usize,
    total_outbound: usize
}

impl SessionStats {
    fn new() -> SessionStats {
        SessionStats{
            start_time: Instant::now(),
            total_timeouts: 0,
            total_responses: 0,
            total_inbound: 0,
            total_outbound: 0
        }
    }

    fn update(&mut self, msg: SessionMessage) {
        match msg {
            SessionMessage::Timeout => self.total_timeouts += 1,
            SessionMessage::Response => self.total_responses += 1,
            SessionMessage::Inbound(x) => self.total_inbound += x,
            SessionMessage::Outbound(x) => self.total_outbound += x,
            _ => ()
        }
    }
}

impl Display for SessionStats {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let duration = self.start_time.elapsed();
        let seconds = ((duration * 1000).as_secs() as f64) / 1000.0;
        write!(f, "timeouts={}\tresponses={}\tdl={}\tbytes/sec\tul={} bytes/sec",
            self.total_timeouts, self.total_responses,
            ((self.total_inbound as f64) / seconds) as u64,
            ((self.total_outbound as f64) / seconds) as u64)
    }
}
