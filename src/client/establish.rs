use myodine::dns_proto::RecordType;

use discovery::Features;
use flags::Flags;

pub struct Establishment {
    pub name_code: String,
    pub record_type: RecordType,
    pub record_code: String,
    pub session_id: u16,
    pub seq_start: u32,
    pub client_mtu: usize,
    pub server_window: u16,
    pub client_window: u16
}

pub fn establish(flags: &Flags, features: Features) -> Result<Establishment, String> {
    // TODO: generate an establishment request.
    // TODO: open socket and send establishment request.
    // TODO: generic API to open outgoing UDP socket.
    // TODO: process establishment request.
    Err(String::from("nyi"))
}
