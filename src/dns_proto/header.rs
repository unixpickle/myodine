use dns_proto::decoding::{Decoder, DecPacket, BitReader};
use dns_proto::encoding::{Encoder, EncPacket, BitWriter};

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

pub struct Header {
    pub identifier: u16,
    pub is_response: bool,
    pub opcode: Opcode,

    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,

    pub response_code: ResponseCode,

    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16
}

impl Encoder for Header {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        self.identifier.dns_encode(packet)?;

        let mut flags = BitWriter::new();
        flags.write_bit(self.is_response);
        flags.write_bits(self.opcode.encode()?, 4);
        flags.write_bit(self.authoritative);
        flags.write_bit(self.truncated);
        flags.write_bit(self.recursion_desired);
        flags.write_bit(self.recursion_available);
        flags.write_bits(0, 3);
        flags.write_bits(self.response_code.encode()?, 4);
        assert!(flags.fits::<u16>());
        (flags.value() as u16).dns_encode(packet)?;

        packet.encode_all(vec![self.question_count, self.answer_count, self.authority_count,
            self.additional_count])
    }
}

impl Decoder for Header {
    fn dns_decode(packet: &mut DecPacket) -> Result<Header, String> {
        let identifier = Decoder::dns_decode(packet)?;

        let mut flags = BitReader::new(u16::dns_decode(packet)? as usize, 16);
        let is_response = flags.read_bit().unwrap();
        let opcode = Opcode::decode(flags.read_bits(4).unwrap());
        let authoritative = flags.read_bit().unwrap();
        let truncated = flags.read_bit().unwrap();
        let recursion_desired = flags.read_bit().unwrap();
        let recursion_available = flags.read_bit().unwrap();
        flags.read_bits(3).unwrap();
        let response_code = ResponseCode::decode(flags.read_bits(4).unwrap());

        let question_count = Decoder::dns_decode(packet)?;
        let answer_count = Decoder::dns_decode(packet)?;
        let authority_count = Decoder::dns_decode(packet)?;
        let additional_count = Decoder::dns_decode(packet)?;

        Ok(Header{
            identifier: identifier,
            is_response: is_response,
            opcode: opcode,
            authoritative: authoritative,
            truncated: truncated,
            recursion_desired: recursion_desired,
            recursion_available: recursion_available,
            response_code: response_code,
            question_count: question_count,
            answer_count: answer_count,
            authority_count: authority_count,
            additional_count: additional_count
        })
    }
}

impl Opcode {
    fn encode(&self) -> Result<usize, String> {
        match *self {
            Opcode::Query => Ok(0),
            Opcode::IQuery => Ok(1),
            Opcode::Status => Ok(2),
            Opcode::Notify => Ok(4),
            Opcode::Update => Ok(5),
            Opcode::Unknown => Err(String::from("unknown opcode"))
        }
    }

    fn decode(value: usize) -> Opcode {
        match value {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            _ => Opcode::Unknown
        }
    }
}

impl ResponseCode {
    fn encode(&self) -> Result<usize, String> {
        match *self {
            ResponseCode::NoError => Ok(0),
            ResponseCode::FormatError => Ok(1),
            ResponseCode::ServerFailure => Ok(2),
            ResponseCode::NXDomain => Ok(3),
            ResponseCode::NotImplemented => Ok(4),
            ResponseCode::Refused => Ok(5),
            ResponseCode::YXDomain => Ok(6),
            ResponseCode::YXRRSet => Ok(7),
            ResponseCode::NXRRSet => Ok(8),
            ResponseCode::NotAuth => Ok(9),
            ResponseCode::NotZone => Ok(10),
            ResponseCode::Unknown => Err(String::from("unknown response code"))
        }
    }

    fn decode(value: usize) -> ResponseCode {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            _ => ResponseCode::Unknown
        }
    }
}
