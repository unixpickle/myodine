use std::iter::FromIterator;
use std::net::Ipv4Addr;

use dns_proto::domain::Domain;
use dns_proto::message::Message;
use dns_proto::record::{Record, RecordHeader, RecordType, RecordBody};

use myo_proto::util::{domain_hash, domain_part_lowercase};
use myo_proto::record_code::get_record_code;

pub fn is_domain_hash_query(query: &Message) -> bool {
    is_discovery_query(query) && query.questions[0].record_type == RecordType::A
}

pub fn is_download_gen_query(query: &Message) -> bool {
    is_discovery_query(query) && query.questions[0].record_type == RecordType::TXT
}

pub fn domain_hash_response(query: &Message) -> Result<Message, String> {
    if !is_domain_hash_query(query) {
        return Err(String::from("not a domain hash query"));
    }
    let mut result = query.clone();
    let question = &query.questions[0];
    let hash = domain_hash(&question.domain);
    result.answers.push(Record{
        header: RecordHeader{
            domain: question.domain.clone(),
            record_type: question.record_type,
            record_class: question.record_class,
            ttl: 0
        },
        body: RecordBody::A(Ipv4Addr::new(hash[0], hash[1], hash[2], hash[3]))
    });
    result.header.answer_count = 1;
    Ok(result)
}

pub fn download_gen_response(query: &Message) -> Result<Message, String> {
    if !is_download_gen_query(query) {
        return Err(String::from("not a download generation query"));
    }
    let question = &query.questions[0];
    let parsed_query = DownloadGenQuery::from_domain(&question.domain)?;
    let encoder = get_record_code(question.record_type, &parsed_query.encoding)
        .ok_or(String::from("no record code found"))?;
    let mut result = query.clone();
    let encoded = encoder.encode_body(&parsed_query.generated_data())?;
    result.answers.push(Record{
        header: RecordHeader{
            domain: question.domain.clone(),
            record_type: question.record_type,
            record_class: question.record_class,
            ttl: 0
        },
        body: encoded
    });
    result.header.answer_count = 1;
    Ok(result)
}

pub struct DownloadGenQuery {
    pub encoding: String,
    pub len: u16,
    pub bias: u8,
    pub coefficient: u8,
    pub modulus: u8
}

impl DownloadGenQuery {
    pub fn from_domain(domain: &Domain) -> Result<DownloadGenQuery, String> {
        if domain.parts().len() < 5 {
            return Err(String::from("not enough domain parts"));
        }
        let encoding = domain.parts()[0].chars().skip(1).collect();
        let len = domain.parts()[1].parse();
        let bias = domain.parts()[2].parse();
        let coefficient = domain.parts()[3].parse();
        let modulus = domain.parts()[4].parse();
        if len.is_err() || bias.is_err() || coefficient.is_err() || modulus.is_err() {
            Err(String::from("invalid number in domain"))
        } else {
            Ok(DownloadGenQuery{
                encoding: encoding,
                len: len.unwrap(),
                bias: bias.unwrap(),
                coefficient: coefficient.unwrap(),
                modulus: modulus.unwrap()
            })
        }
    }

    pub fn generated_data(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..self.len {
            let value = ((i as u64) + (self.bias as u64)) * (self.coefficient as u64) %
                (self.modulus as u64);
            result.push(value as u8);
        }
        result
    }
}

fn is_discovery_query(query: &Message) -> bool {
    if !query.header.is_response &&
        query.questions.len() == 1 &&
        query.answers.len() == 0 &&
        query.authorities.len() == 0 &&
        query.additional.len() == 0 &&
        query.questions[0].domain.parts().len() > 0 {
        let first = &query.questions[0].domain.parts()[0];
        domain_part_lowercase(first).chars().next().unwrap() == 'f'
    } else {
        false
    }
}
