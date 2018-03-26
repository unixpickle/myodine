use std::net::TcpStream;
use std::time::{Duration, Instant};

use myodine::conn::TcpChunker;
use myodine::dns_proto::record::RecordType;
use myodine::myo_proto::establish::EstablishQuery;
use myodine::myo_proto::name_code::{NameCode, get_name_code};
use myodine::myo_proto::record_code::{RecordCode, get_record_code};
use myodine::myo_proto::xfer::{ClientPacket, Packet, WwrState};

pub struct Session {
    id: u16,
    last_used: Instant,
    state: WwrState,
    name_code: Box<NameCode>,
    record_code: Box<RecordCode>,
    conn: TcpChunker
}

impl Session {
    pub fn new(
        id: u16,
        seq_start: u32,
        query_type: RecordType,
        query: &EstablishQuery,
        timeout: Duration
    ) -> Result<Session, String> {
        let name_code = get_name_code(&query.name_encoding).ok_or(String::from("bad name code"))?;
        let record_code = get_record_code(query_type, &query.response_encoding)
            .ok_or(String::from("bad record code"))?;
        let addr_str = format!("{}:{}", query.host, query.port);
        let addr = addr_str.parse().map_err(|e| format!("{}", e))?;
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("connect error: {}", e))?;
        let conn = TcpChunker::new(stream, query.mtu as usize, query.send_window as usize,
                query.recv_window as usize).map_err(|e| format!("chunker error: {}", e))?;
        Ok(Session{
            id: id,
            last_used: Instant::now(),
            state: WwrState::new(query.recv_window, query.send_window, seq_start),
            name_code: name_code,
            record_code: record_code,
            conn: conn,
        })
    }

    pub fn session_id(&self) -> u16 {
        self.id
    }

    pub fn timed_out(&self, timeout: Duration) -> bool {
        Instant::now() - self.last_used > timeout
    }

    pub fn handle_packet(&mut self, packet: ClientPacket) -> Packet {
        // TODO: verify packet using sequence number!
        self.last_used = Instant::now();
        self.state.handle_ack(&packet.packet.ack);
        if self.conn.can_send() && packet.packet.chunk.is_some() {
            let mut buffer = Vec::new();
            let mut finished = false;
            for chunk in self.state.handle_chunk(packet.packet.chunk.unwrap()) {
                if chunk.data.len() == 0 {
                    finished = true;
                    break; // Data past EOF is meaningless.
                } else {
                    buffer.extend(chunk.data);
                }
            }
            if buffer.len() > 0 {
                self.conn.send(buffer);
            }
            if finished {
                self.conn.send_finished();
            }
        }
        while self.state.send_buffer_space() > 0 {
            if let Some(data) = self.conn.recv() {
                self.state.push_send_buffer(data);
            } else {
                break;
            }
        }
        Packet{
            ack: self.state.next_send_ack(),
            chunk: self.state.next_send_chunk()
        }
    }
}
