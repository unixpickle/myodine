use dns_proto::decoding::{Decoder, DecPacket};
use dns_proto::encoding::{Encoder, EncPacket};

pub enum Opcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Unknown
}

pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NXDomain,
    NotImplemented,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Unknown
}

struct Header {
    pub Identifier: u16,
    pub IsResponse: bool,
    pub Opcode: Opcode,

    pub Authoritative: bool,
    pub Truncated: bool,
    pub RecursionDesired: bool,
    pub RecursionAvailable: bool,

    pub ResponseCode: ResponseCode,

    pub QuestionCount: u16,
    pub AnswerCount: u16,
    pub AuthorityCount: u16,
    pub AdditionalCount: u16
}
//
// impl Encoder for Header {
//     fn dns_encode(&self, packet: &mut EncPacket) {
//     }
// }
//
// impl Decoder for Header {
//     fn dns_decode(packet: &mut DecPacket) -> Result<Header, String> {
//     }
// }
