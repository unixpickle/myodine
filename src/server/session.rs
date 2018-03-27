use std::net::TcpStream;
use std::time::{Duration, Instant};

use myodine::conn::TcpChunker;
use myodine::dns_coding::dns_encode;
use myodine::dns_proto::domain::Domain;
use myodine::dns_proto::message::Message;
use myodine::dns_proto::record::{Record, RecordHeader, RecordType};
use myodine::myo_proto::establish::EstablishQuery;
use myodine::myo_proto::name_code::{NameCode, get_name_code};
use myodine::myo_proto::record_code::{RecordCode, get_record_code};
use myodine::myo_proto::xfer::{ClientPacket, Packet, WwrState, handle_packet_in, next_packet_out};

pub struct Session {
    id: u16,
    last_used: Instant,
    state: WwrState,
    name_code: Box<NameCode>,
    record_code: Box<RecordCode>,
    conn: TcpChunker,
    send_window: u16
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
            send_window: query.send_window
        })
    }

    pub fn session_id(&self) -> u16 {
        self.id
    }

    pub fn timed_out(&self, timeout: Duration) -> bool {
        Instant::now() - self.last_used > timeout
    }

    pub fn handle_message(&mut self, message: Message, host: &Domain) -> Result<Message, String> {
        let (api, _, data) = self.name_code.decode_domain(&message.questions[0].domain, host)?;
        // TODO: is this the correct window size to be using?
        let in_packet = ClientPacket::decode(api, data, self.send_window)?;
        let response_packet = self.handle_packet(in_packet);
        let mut response = message;
        let record = Record{
            header: RecordHeader{
                domain: response.questions[0].domain.clone(),
                record_type: response.questions[0].record_type,
                record_class: response.questions[0].record_class,
                ttl: 0,
            },
            body: self.record_code.encode_body(&dns_encode(&response_packet)?)?
        };
        response.answers.push(record);
        response.header.is_response = true;
        response.header.answer_count = 1;
        Ok(response)
    }

    fn handle_packet(&mut self, packet: ClientPacket) -> Packet {
        // TODO: verify packet using sequence number!
        self.last_used = Instant::now();
        handle_packet_in(packet.packet, &mut self.state, &mut self.conn);
        next_packet_out(&mut self.state, &mut self.conn)
    }
}
