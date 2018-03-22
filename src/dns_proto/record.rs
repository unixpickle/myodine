use std::net::{Ipv4Addr, Ipv6Addr};

use dns_proto::domain::Domain;

pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    Unknown(u16)
}

pub enum RecordClass {
    IN,
    Unknown(u16)
}

pub struct RecordHeader {
    pub domain: Domain,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32
}

pub struct SOADetails {
    pub master_name: Domain,
    pub responsible_name: Domain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32
}

pub enum Record {
    ARecord(RecordHeader, Ipv4Addr),
    AAAARecord(RecordHeader, Ipv6Addr),
    DomainRecord(RecordHeader, Domain),
    SOARecord(RecordHeader, SOADetails),
    Unknown(RecordHeader, Vec<u8>)
}

// impl Encoder for Record {
//     fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
//         // TODO: this.
//     }
// }

// impl Decoder for Record {
//     fn dns_decode(packet: &mut DecPacket) -> Result<Record, String> {
//         // TODO: this.
//     }
// }

impl RecordType {
    fn encode(&self) -> u16 {
        match *self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::Unknown(x) => x
        }
    }

    fn decode(value: u16) -> RecordType {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            _ => RecordType::Unknown(value)
        }
    }
}

impl RecordClass {
    fn encode(&self) -> u16 {
        match *self {
            RecordClass::IN => 1,
            RecordClass::Unknown(x) => x
        }
    }

    fn decode(value: u16) -> RecordClass {
        match value {
            1 => RecordClass::IN,
            _ => RecordClass::Unknown(value)
        }
    }
}
