use std::net::TcpStream;
use std::time::{Duration, Instant};

use myodine::conn::TcpChunker;
use myodine::dns_proto::{Domain, Message, Record, RecordHeader, RecordType};
use myodine::myo_proto::establish::EstablishQuery;
use myodine::myo_proto::name_code::{NameCode, get_name_code};
use myodine::myo_proto::record_code::{RecordCode, get_record_code};
use myodine::myo_proto::xfer::{Packet, WwrState, handle_packet_in, next_packet_out};

/// The state of a single session.
pub struct Session {
    id: u16,
    last_used: Instant,
    state: WwrState,
    name_code: Box<NameCode>,
    record_code: Box<RecordCode>,
    conn: TcpChunker,
    response_window: u16
}

impl Session {
    /// Establish a new session.
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
        let addr = addr_str.parse().map_err(|e| format!("parse {}: {}", addr_str, e))?;
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("connect error: {}", e))?;
        // TCP buffer sizes are chosen rather arbitrarily.
        let conn = TcpChunker::new(stream, query.mtu as usize, query.response_window as usize,
                query.query_window as usize).map_err(|e| format!("chunker error: {}", e))?;
        Ok(Session{
            id: id,
            last_used: Instant::now(),
            state: WwrState::new(query.query_window, query.response_window, seq_start),
            name_code: name_code,
            record_code: record_code,
            conn: conn,
            response_window: query.response_window
        })
    }

    /// Get this session's ID.
    pub fn session_id(&self) -> u16 {
        self.id
    }

    /// Check if the session is done or timed out.
    pub fn is_done(&self, timeout: Duration) -> bool {
        self.state.is_done() || Instant::now() - self.last_used > timeout
    }

    /// Handle a message that was directed to the session.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was received.
    /// * `host` - The root domain name of the server.
    pub fn handle_message(&mut self, message: Message, host: &Domain) -> Result<Message, String> {
        let (api, _, data) = self.name_code.decode_domain(&message.questions[0].domain, host)?;
        let in_packet = Packet::decode_query(&data, self.response_window, api)?;
        let response_packet = self.handle_packet(in_packet);
        let mut response = message;
        let record = Record{
            header: RecordHeader{
                domain: response.questions[0].domain.clone(),
                record_type: response.questions[0].record_type,
                record_class: response.questions[0].record_class,
                ttl: 0,
            },
            body: self.record_code.encode_body(&response_packet.encode_response()?)?
        };
        response.answers.push(record);
        response.header.is_response = true;
        response.header.answer_count = 1;
        Ok(response)
    }

    fn handle_packet(&mut self, packet: Packet) -> Packet {
        // TODO: verify packet using sequence number!
        self.last_used = Instant::now();
        handle_packet_in(packet, &mut self.state, &mut self.conn);
        next_packet_out(&mut self.state, &mut self.conn)
    }
}
