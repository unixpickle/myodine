use dns_proto::domain::Domain;
use dns_proto::record::{RecordType, RecordClass};
use dns_proto::encoding::{Encoder, EncPacket};
use dns_proto::decoding::{Decoder, DecPacket};

pub struct Question {
    domain: Domain,
    record_type: RecordType,
    record_class: RecordClass
}

impl Encoder for Question {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        self.domain.dns_encode(packet)?;
        self.record_type.dns_encode(packet)?;
        self.record_class.dns_encode(packet)?;
        Ok(())
    }
}

impl Decoder for Question {
    fn dns_decode(packet: &mut DecPacket) -> Result<Question, String> {
        let domain = Decoder::dns_decode(packet)?;
        let record_type = Decoder::dns_decode(packet)?;
        let record_class = Decoder::dns_decode(packet)?;
        Ok(Question{
            domain: domain,
            record_type: record_type,
            record_class: record_class
        })
    }
}
