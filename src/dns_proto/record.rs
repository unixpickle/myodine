use std::net::{Ipv4Addr, Ipv6Addr};

use dns_coding::{Decoder, DecPacket, Encoder, EncPacket};
use super::domain::Domain;

#[derive(PartialEq, Clone, Copy, Debug)]
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

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum RecordClass {
    IN,
    Unknown(u16)
}

#[derive(PartialEq, Clone, Debug)]
pub struct RecordHeader {
    pub domain: Domain,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32
}

#[derive(PartialEq, Clone, Debug)]
pub struct SOADetails {
    pub master_name: Domain,
    pub responsible_name: Domain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32
}

#[derive(PartialEq, Clone, Debug)]
pub enum RecordBody {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Domain(Domain),
    SOA(SOADetails),
    Unknown(Vec<u8>)
}

#[derive(PartialEq, Clone, Debug)]
pub struct Record {
    pub header: RecordHeader,
    pub body: RecordBody
}

impl Encoder for Record {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        encode_all!(packet, self.header.domain, self.header.record_type,
            self.header.record_class, self.header.ttl)?;
        packet.encode_with_length(|packet| {
            match self.body {
                RecordBody::A(ref addr) => addr.octets().to_vec().dns_encode(packet),
                RecordBody::AAAA(ref addr) => addr.octets().to_vec().dns_encode(packet),
                RecordBody::Domain(ref name) => name.dns_encode(packet),
                RecordBody::SOA(ref soa) => {
                    encode_all!(packet, soa.master_name, soa.responsible_name, soa.serial,
                        soa.refresh, soa.retry, soa.expire, soa.minimum)
                },
                RecordBody::Unknown(ref data) => data.dns_encode(packet)
            }
        })
    }
}

impl Decoder for Record {
    fn dns_decode(packet: &mut DecPacket) -> Result<Record, String> {
        let domain = Decoder::dns_decode(packet)?;
        let record_type = Decoder::dns_decode(packet)?;
        let record_class = Decoder::dns_decode(packet)?;
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
                    RecordType::A => RecordBody::A(From::from(u32::dns_decode(packet)?)),
                    RecordType::AAAA => {
                        let data = packet.read_bytes(16)?;
                        let mut buffer = [0u8; 16];
                        for i in 0..16 {
                            buffer[i] = data[i];
                        }
                        RecordBody::AAAA(From::from(buffer))
                    },
                    RecordType::NS | RecordType::CNAME | RecordType::PTR => {
                        RecordBody::Domain(Domain::dns_decode(packet)?)
                    },
                    RecordType::SOA => {
                        let master_name = Decoder::dns_decode(packet)?;
                        let responsible_name = Decoder::dns_decode(packet)?;
                        let nums: Vec<u32> = packet.decode_all(5)?;
                        RecordBody::SOA(SOADetails{
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

impl Encoder for RecordType {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        (match *self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::Unknown(x) => x
        } as u16).dns_encode(packet)
    }
}

impl Encoder for RecordClass {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        (match *self {
            RecordClass::IN => 1,
            RecordClass::Unknown(x) => x
        } as u16).dns_encode(packet)
    }
}

impl Decoder for RecordType {
    fn dns_decode(packet: &mut DecPacket) -> Result<RecordType, String> {
        Ok(match u16::dns_decode(packet)? {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            x => RecordType::Unknown(x)
        })
    }
}

impl Decoder for RecordClass {
    fn dns_decode(packet: &mut DecPacket) -> Result<RecordClass, String> {
        Ok(match u16::dns_decode(packet)? {
            1 => RecordClass::IN,
            x => RecordClass::Unknown(x)
        })
    }
}
