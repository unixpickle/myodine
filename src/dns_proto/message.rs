use dns_proto::domain::Domain;
use dns_proto::record::{RecordType, RecordClass, Record};
use dns_proto::encoding::{Encoder, EncPacket};
use dns_proto::decoding::{Decoder, DecPacket};
use dns_proto::header::Header;

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
        Ok(Message{
            header: header,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additional: additional
        })
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
