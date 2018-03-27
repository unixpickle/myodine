use dns_coding::{Encoder, EncPacket, Decoder, DecPacket};
use super::domain::Domain;
use super::header::Header;
use super::record::{RecordType, RecordClass, Record};

#[derive(PartialEq, Clone, Debug)]
pub struct Question {
    pub domain: Domain,
    pub record_type: RecordType,
    pub record_class: RecordClass
}

#[derive(PartialEq, Clone, Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additional: Vec<Record>
}

impl Encoder for Message {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        if self.questions.len() != self.header.question_count as usize ||
            self.answers.len() != self.header.answer_count as usize ||
            self.authorities.len() != self.header.authority_count as usize ||
            self.additional.len() != self.header.additional_count as usize {
            Err(String::from("mismatching length in header and vector"))
        } else {
            encode_all!(packet, self.header, self.questions, self.answers, self.authorities,
                self.additional)
        }
    }
}

impl Decoder for Message {
    fn dns_decode(packet: &mut DecPacket) -> Result<Message, String> {
        let header = Header::dns_decode(packet)?;
        let questions = packet.decode_all(header.question_count as usize)?;
        let answers = packet.decode_all(header.answer_count as usize)?;
        let authorities = packet.decode_all(header.authority_count as usize)?;
        let additional = packet.decode_all(header.additional_count as usize)?;
        if packet.remaining() > 0 {
            Err(String::from("trailing data in packet"))
        } else {
            Ok(Message{
                header: header,
                questions: questions,
                answers: answers,
                authorities: authorities,
                additional: additional
            })
        }
    }
}

impl Encoder for Question {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        encode_all!(packet, self.domain, self.record_type, self.record_class)
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

#[cfg(test)]
mod tests {
    use super::*;
    use dns_coding::{dns_decode, dns_encode};
    use dns_proto::header::Opcode;
    use dns_proto::record::RecordBody;

    #[test]
    fn aaaa_request() {
        let request = [0x4Du8, 0xB1u8, 0x01u8, 0x00u8, 0x00u8, 0x01u8, 0x00u8, 0x00u8,
                       0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x03u8, 0x66u8, 0x6Fu8, 0x6Fu8,
                       0x03u8, 0x63u8, 0x6Fu8, 0x6Du8, 0x00u8, 0x00u8, 0x1Cu8, 0x00u8,
                       0x01u8];
        let message: Message = dns_decode(request.clone().to_vec()).unwrap();
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 0);
        assert_eq!(message.authorities.len(), 0);
        assert_eq!(message.additional.len(), 0);
        assert_eq!(message.header.opcode, Opcode::Query);
        assert_eq!(message.header.identifier, 0x4db1);
        assert!(!message.header.is_response);
        assert!(message.header.recursion_desired);
        let question = &message.questions[0];
        assert_eq!(question.domain, "foo.com".parse().unwrap());
        assert_eq!(question.record_type, RecordType::AAAA);
        assert_eq!(question.record_class, RecordClass::IN);
        assert_eq!(request.to_vec(), dns_encode(&message).unwrap());
    }

    #[test]
    fn soa_response() {
        let response = [0x4Du8, 0xB1u8, 0x81u8, 0x80u8, 0x00u8, 0x01u8, 0x00u8, 0x00u8,
                        0x00u8, 0x01u8, 0x00u8, 0x00u8, 0x03u8, 0x66u8, 0x6Fu8, 0x6Fu8,
                        0x03u8, 0x63u8, 0x6Fu8, 0x6Du8, 0x00u8, 0x00u8, 0x1Cu8, 0x00u8,
                        0x01u8, 0xC0u8, 0x0Cu8, 0x00u8, 0x06u8, 0x00u8, 0x01u8, 0x00u8,
                        0x00u8, 0x02u8, 0x57u8, 0x00u8, 0x2Au8, 0x03u8, 0x6Eu8, 0x73u8,
                        0x31u8, 0x09u8, 0x64u8, 0x69u8, 0x67u8, 0x69u8, 0x6Du8, 0x65u8,
                        0x64u8, 0x69u8, 0x61u8, 0xC0u8, 0x10u8, 0x03u8, 0x64u8, 0x6Eu8,
                        0x73u8, 0xC0u8, 0x29u8, 0x78u8, 0x3Au8, 0xD0u8, 0x92u8, 0x00u8,
                        0x00u8, 0x2Au8, 0x30u8, 0x00u8, 0x00u8, 0x0Eu8, 0x10u8, 0x00u8,
                        0x09u8, 0x3Au8, 0x80u8, 0x00u8, 0x00u8, 0x0Eu8, 0x10u8];
        let message: Message = dns_decode(response.clone().to_vec()).unwrap();
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 0);
        assert_eq!(message.authorities.len(), 1);
        assert_eq!(message.additional.len(), 0);
        assert_eq!(message.header.opcode, Opcode::Query);
        assert_eq!(message.header.identifier, 0x4db1);
        assert!(message.header.is_response);
        assert!(message.header.recursion_desired);
        assert!(message.header.recursion_available);
        let question = &message.questions[0];
        assert_eq!(question.domain, "foo.com".parse().unwrap());
        assert_eq!(question.record_type, RecordType::AAAA);
        assert_eq!(question.record_class, RecordClass::IN);
        let soa = &message.authorities[0];
        assert_eq!(soa.header.domain, "foo.com".parse().unwrap());
        assert_eq!(soa.header.record_type, RecordType::SOA);
        assert_eq!(soa.header.record_class, RecordClass::IN);
        assert_eq!(soa.header.ttl, 599);
        match &soa.body {
            &RecordBody::SOA(ref info) => {
                assert_eq!(info.master_name, "ns1.digimedia.com".parse().unwrap());
                assert_eq!(info.responsible_name, "dns.digimedia.com".parse().unwrap());
                assert_eq!([info.serial, info.refresh, info.retry, info.expire, info.minimum],
                    [2017120402, 10800, 3600, 604800, 3600]);
            },
            _ => panic!("expected SOARecord")
        }
        assert_eq!(dns_decode::<Message>(dns_encode(&message).unwrap()).unwrap(), message);
    }
}
