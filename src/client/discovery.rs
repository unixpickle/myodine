use myodine::dns_proto::domain::Domain;
use myodine::dns_proto::record::RecordType;

pub struct Features {
    pub receive_record_type: RecordType,
    pub receive_code: String,
    pub receive_mtu: usize,
    pub send_code: String,
    pub send_mtu: usize
}

pub fn discover_features(address: &str, host: &Domain) -> Result<Features, String> {
    // TODO: perform feature discovery here.
    Ok(Features{
        receive_record_type: RecordType::TXT,
        receive_code: String::from("raw"),
        receive_mtu: 64,
        send_code: String::from("b16"),
        send_mtu: 64
    })
}
