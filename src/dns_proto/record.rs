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
