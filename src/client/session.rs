use std::io;
use std::mem::replace;
use std::net::TcpStream;
use std::process::exit;
use std::sync::mpsc::{Receiver, Sender, channel};

use myodine::conn::{Highway, Event, TcpChunker};
use myodine::dns_coding::dns_decode;
use myodine::dns_proto::{Message, RecordType};
use myodine::myo_proto::establish::{EstablishQuery, EstablishResponse};
use myodine::myo_proto::name_code::{NameCode, get_name_code};
use myodine::myo_proto::record_code::{RecordCode, get_record_code};
use myodine::myo_proto::xfer::{WwrState, Packet};

use flags::Flags;
use establish::Establishment;

pub struct Session {
    name_code: Box<NameCode>,
    record_code: Box<RecordCode>,
    highway: Highway,
    state: WwrState,
    conn: TcpChunker,
    events: Option<Receiver<Event>>,
    info: Establishment
}

impl Session {
    pub fn new(flags: &Flags, conn: TcpStream, info: Establishment) -> io::Result<Session>
    {
        let (highway, events) = Highway::open(&flags.addr, flags.concurrency);
        let conn = TcpChunker::new(conn, info.client_mtu as usize, info.client_window as usize,
                info.server_window as usize)?;
        Ok(Session{
            name_code: get_name_code(&info.name_code).unwrap(),
            record_code: get_record_code(info.record_type, &info.record_code).unwrap(),
            highway: highway,
            state: WwrState::new(info.server_window, info.client_window, info.seq_start),
            conn: conn,
            events: Some(events),
            info: info
        })
    }

    pub fn run(&mut self, log: &Sender<String>) -> Result<(), String> {
        for event in replace(&mut self.events, None).unwrap() {
            match event {
                Event::Response(lane, msg) => {
                    self.handle_message(msg);
                    self.populate_lane(lane);
                },
                Event::Timeout(lane) => {
                    self.populate_lane(lane);
                },
                Event::SendError(lane, msg) => {
                    log.send(format!("lane {}: error sending message: {}", lane, msg)).unwrap();
                },
                Event::ConnectError(lane, err) => {
                    return Err(format!("lane {}: error connecting: {}", lane, err));
                },
                Event::SocketError(lane, err) => {
                    return Err(format!("lane {}: error on socket: {}", lane, err));
                }
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.answers.len() != 1 {
            return;
        }
        if let Ok(raw_body) = self.record_code.decode_body(&msg.answers[0].body) {
            if let Ok(packet) = Packet::decode_response(&raw_body, self.info.server_window) {
                self.handle_packet(packet);
            }
        }
    }

    fn handle_packet(&mut self, packet: Packet) {
        // TODO: reuse the code from server::session::Session::handle_packet.
    }

    fn populate_lane(&mut self, lane: usize) {
        // TODO: squeeze as much data as possible from self.conn.
        // TODO: pull a chunk out of data out of self.state.
    }
}
