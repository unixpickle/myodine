use std::net::{Ipv4Addr, Ipv6Addr};

use dns_proto::domain::Domain;
use dns_proto::decoding::{Decoder, DecPacket};
use dns_proto::encoding::{Encoder, EncPacket};

#[derive(Clone, Copy)]
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

#[derive(Clone, Copy)]
pub enum RecordClass {
    IN,
    Unknown(u16)
}

#[derive(Clone)]
pub struct RecordHeader {
    pub domain: Domain,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32
}

#[derive(Clone)]
pub struct SOADetails {
    pub master_name: Domain,
    pub responsible_name: Domain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32
}

#[derive(Clone)]
pub enum RecordBody {
    ARecord(Ipv4Addr),
    AAAARecord(Ipv6Addr),
    DomainRecord(Domain),
    SOARecord(SOADetails),
    Unknown(Vec<u8>)
}

#[derive(Clone)]
pub struct Record {
    pub header: RecordHeader,
    pub body: RecordBody
}

impl Encoder for Record {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        self.header.domain.dns_encode(packet)?;
        self.header.record_type.encode().dns_encode(packet)?;
        self.header.record_class.encode().dns_encode(packet)?;
        self.header.ttl.dns_encode(packet)?;
        packet.encode_with_length(|packet| {
            match self.body {
                RecordBody::ARecord(ref addr) => packet.encode_all(addr.octets().to_vec()),
                RecordBody::AAAARecord(ref addr) => packet.encode_all(addr.octets().to_vec()),
                RecordBody::DomainRecord(ref name) => name.dns_encode(packet),
                RecordBody::SOARecord(ref soa) => {
                    soa.master_name.dns_encode(packet)?;
                    soa.responsible_name.dns_encode(packet)?;
                    packet.encode_all(vec![soa.serial, soa.refresh, soa.retry, soa.expire,
                        soa.minimum])
                },
                RecordBody::Unknown(ref data) => packet.encode_all(data.clone())
            }
        })
    }
}

impl Decoder for Record {
    fn dns_decode(packet: &mut DecPacket) -> Result<Record, String> {
        let domain = Decoder::dns_decode(packet)?;
        let record_type = RecordType::decode(Decoder::dns_decode(packet)?);
        let record_class = RecordClass::decode(Decoder::dns_decode(packet)?);
        let ttl = Decoder::dns_decode(packet)?;
        Ok(Record{
            header: RecordHeader{
                domain: domain,
                record_type: record_type,
                record_class: record_class,
                ttl: ttl
            },
            body: packet.decode_with_length(|packet, len| {
                Ok(match record_type {
                    RecordType::A => RecordBody::ARecord(From::from(u32::dns_decode(packet)?)),
                    RecordType::AAAA => {
                        let data = packet.read_bytes(16)?;
                        let mut buffer = [0u8; 16];
                        for i in 0..16 {
                            buffer[i] = data[i];
                        }
                        RecordBody::AAAARecord(From::from(buffer))
                    },
                    RecordType::NS | RecordType::CNAME | RecordType::PTR => {
                        RecordBody::DomainRecord(Domain::dns_decode(packet)?)
                    },
                    RecordType::SOA => {
                        let master_name = Decoder::dns_decode(packet)?;
                        let responsible_name = Decoder::dns_decode(packet)?;
                        let nums: Vec<u32> = packet.decode_all(5)?;
                        RecordBody::SOARecord(SOADetails{
                            master_name: master_name,
                            responsible_name: responsible_name,
                            serial: nums[0],
                            refresh: nums[1],
                            retry: nums[2],
                            expire: nums[3],
                            minimum: nums[4]
                        })
                    },
                    _ => RecordBody::Unknown(packet.read_bytes(len)?)
                })
            })?
        })
    }
}

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
