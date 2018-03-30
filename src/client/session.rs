use std::net::TcpStream;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use myodine::conn::{Highway, Event, TcpChunker};
use myodine::dns_proto::{Domain, Message, Question, RecordClass};
use myodine::myo_proto::xfer::{Packet, WwrState, handle_packet_in, next_packet_out};

use flags::Flags;
use establish::Establishment;
use logger::{RawLogger, SessionLogger};

pub fn run_session(
    flags: Flags,
    conn: TcpStream,
    info: Establishment,
    logger: &RawLogger
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
        query_max_time: flags.query_max_time,
        logger: SessionLogger::new(logger.clone())
    };
    session.run(events)
}

struct Session {
    highway: Highway,
    state: WwrState,
    conn: TcpChunker,
    info: Establishment,
    host: Domain,
    query_min_time: Duration,
    query_max_time: Duration,
    logger: SessionLogger
}

impl Session {
    pub fn run(&mut self, events: Receiver<Event>) -> Result<(), String> {
        for lane in 0..self.highway.num_lanes() {
            self.populate_lane(lane)?;
        }
        for event in events {
            match event {
                Event::Response(lane, msg) => {
                    self.logger.log_response();
                    self.handle_message(msg);
                    self.populate_lane(lane)?;
                },
                Event::Timeout(lane) => {
                    self.logger.log_timeout();
                    self.populate_lane(lane)?;
                },
                Event::SendError(lane, msg) => {
                    self.logger.log_raw(format!("lane {}: error sending message: {}", lane, msg));
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

    fn handle_message(&mut self, msg: Message) {
        if msg.answers.len() != 1 || msg.header.truncated {
            self.logger.log_raw(format!("invalid response (truncated={}, answers={})",
                msg.header.truncated, msg.answers.len()));
            return;
        }
        if let Ok(raw_body) = self.info.record_code.decode_body(&msg.answers[0].body) {
            if let Ok(packet) = Packet::decode_response(&raw_body, self.info.query_window) {
                self.handle_packet(packet);
            }
        }
    }

    fn handle_packet(&mut self, packet: Packet) {
        self.logger.log_inbound(handle_packet_in(packet, &mut self.state, &mut self.conn));
    }

    fn populate_lane(&mut self, lane: usize) -> Result<(), String> {
        let (packet, sent_size) = next_packet_out(&mut self.state, &mut self.conn);
        self.logger.log_outbound(sent_size);
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
