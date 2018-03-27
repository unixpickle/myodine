use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use myodine::conn::dial_udp;
use myodine::dns_coding::{dns_decode, dns_encode};
use myodine::dns_proto::{Message, Question, RecordClass, RecordType};
use myodine::myo_proto::establish::{EstablishQuery, EstablishResponse, password_proof};
use myodine::myo_proto::name_code::NameCode;
use myodine::myo_proto::record_code::RecordCode;

use discovery::Features;
use flags::Flags;

pub struct Establishment {
    pub name_code: Box<NameCode>,
    pub record_code: Box<RecordCode>,
    pub record_type: RecordType,
    pub session_id: u16,
    pub seq_start: u32,
    pub query_mtu: u16,
    pub response_mtu: u16,
    pub query_window: u16,
    pub response_window: u16
}

pub fn establish(flags: &Flags, features: Features) -> Result<Establishment, String> {
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let query = EstablishQuery{
        response_encoding: features.response_encoding,
        mtu: features.response_mtu,
        name_encoding: features.name_encoding,
        query_window: flags.query_window,
        response_window: flags.response_window,
        proof: password_proof(&flags.password, epoch),
        port: flags.remote_port,
        host: flags.remote_host.clone()
    };
    let message = Message::new_query(Question{
        domain: query.to_domain(&flags.host)?,
        record_type: features.record_type,
        record_class: RecordClass::IN
    });
    let conn = dial_udp(&flags.addr).map_err(|e| format!("dial {}: {}", flags.addr, e))?;
    conn.set_read_timeout(Some(Duration::new(5, 0))).map_err(|e| format!("{}", e))?;
    let response = query_with_retries(&conn, &message, 5)
        .ok_or(String::from("no establishment response"))?;
    if response.answers.len() != 1 {
        return Err(String::from("invalid response message"));
    }
    let raw_data = features.record_code.decode_body(&response.answers[0].body)?;
    match dns_decode(raw_data)? {
        EstablishResponse::Success{id, seq} => {
            Ok(Establishment{
                name_code: features.name_code,
                record_code: features.record_code,
                record_type: features.record_type,
                session_id: id,
                seq_start: seq,
                query_mtu: features.query_mtu,
                response_mtu: features.response_mtu,
                query_window: flags.query_window,
                response_window: flags.response_window
            })
        },
        EstablishResponse::Failure(msg) => {
            Err(format!("error from server: {}", msg))
        },
        EstablishResponse::Unknown(x) => {
            Err(format!("unknown establishment response type: {}", x))
        }
    }
}

fn query_with_retries(conn: &UdpSocket, msg: &Message, tries: usize) -> Option<Message> {
    for _ in 0..tries {
        if let Ok(msg) = attempt_query(conn, msg) {
            return Some(msg);
        }
    }
    None
}

fn attempt_query(conn: &UdpSocket, msg: &Message) -> Result<Message, String> {
    conn.send(&dns_encode(msg)?).map_err(|e| format!("{}", e))?;
    let mut res_data = [0u8; 2048];
    let size = conn.recv(&mut res_data).map_err(|e| format!("{}", e))?;
    let res = dns_decode::<Message>(res_data[..size].to_vec())?;
    if res.header.identifier == msg.header.identifier {
        Ok(res)
    } else {
        Err(String::from("bad response identifier"))
    }
}
