use myodine::dns_proto::{Domain, RecordType};
use myodine::myo_proto::name_code::{NameCode, get_name_code};
use myodine::myo_proto::record_code::{RecordCode, get_record_code};

pub struct Features {
    pub record_type: RecordType,
    pub response_encoding: String,
    pub response_mtu: u16,
    pub name_encoding: String,
    pub query_mtu: u16,
    pub name_code: Box<NameCode>,
    pub record_code: Box<RecordCode>
}

pub fn discover_features(_address: &str, _host: &Domain) -> Result<Features, String> {
    // TODO: perform feature discovery here.
    Ok(Features{
        record_type: RecordType::TXT,
        response_encoding: String::from("raw"),
        response_mtu: 64,
        name_encoding: String::from("b16"),
        query_mtu: 64,
        name_code: get_name_code("b16").unwrap(),
        record_code: get_record_code(RecordType::TXT, "raw").unwrap()
    })
}
