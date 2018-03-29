use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use myodine::conn::{Highway, Event, TcpChunker};
use myodine::dns_proto::{Domain, Message, Question, RecordClass};
use myodine::myo_proto::xfer::{Packet, WwrState, handle_packet_in, next_packet_out};

use flags::Flags;
use establish::Establishment;

pub fn run_session(
    flags: Flags,
    conn: TcpStream,
    info: Establishment,
    log: &Sender<String>
) -> Result<(), String> {
    let (highway, events) = Highway::open(&flags.addr, flags.concurrency);
    let conn = TcpChunker::new(
        conn,
        info.query_mtu as usize,
        info.query_window as usize,
        info.response_window as usize
    ).map_err(|e| format!("error creating chunker: {}", e))?;
    let mut session = Session{
        highway: highway,
        state: WwrState::new(info.response_window, info.query_window, info.seq_start),
        conn: conn,
        info: info,
        host: flags.host,
        query_min_time: flags.query_min_time,
        query_max_time: flags.query_max_time
    };
    session.run(log, events)
}

struct Session {
    highway: Highway,
    state: WwrState,
    conn: TcpChunker,
    info: Establishment,
    host: Domain,
    query_min_time: Duration,
    query_max_time: Duration
}

impl Session {
    pub fn run(&mut self, log: &Sender<String>, events: Receiver<Event>) -> Result<(), String> {
        for lane in 0..self.highway.num_lanes() {
            self.populate_lane(lane)?;
        }
        for event in events {
            match event {
                Event::Response(lane, msg) => {
                    self.handle_message(log, msg);
                    self.populate_lane(lane)?;
                },
                Event::Timeout(lane) => {
                    log.send(format!("lane {}: timeout", lane)).unwrap();
                    self.populate_lane(lane)?;
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
            if self.state.is_done() {
                break;
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, log: &Sender<String>, msg: Message) {
        if msg.answers.len() != 1 || msg.header.truncated {
            log.send(format!("invalid response (truncated={}, answers={})", msg.header.truncated,
                msg.answers.len())).unwrap();
            return;
        }
        if let Ok(raw_body) = self.info.record_code.decode_body(&msg.answers[0].body) {
            if let Ok(packet) = Packet::decode_response(&raw_body, self.info.query_window) {
                self.handle_packet(packet);
            }
        }
    }

    fn handle_packet(&mut self, packet: Packet) {
        handle_packet_in(packet, &mut self.state, &mut self.conn);
    }

    fn populate_lane(&mut self, lane: usize) -> Result<(), String> {
        let packet = next_packet_out(&mut self.state, &mut self.conn);
        let (api_code, data) = packet.encode_query()?;
        let message = Message::new_query(Question{
            domain: self.info.name_code.encode_domain(api_code, self.info.session_id, &data,
                &self.host)?,
            record_type: self.info.record_type,
            record_class: RecordClass::IN
        });
        self.highway.send(lane, message, self.query_min_time, self.query_max_time);
        Ok(())
    }
}
