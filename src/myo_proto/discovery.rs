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
        if len.is_err() || bias.is_err() || coefficient.is_err() || modulus.is_err() ||
            *modulus.as_ref().unwrap() < 2 {
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

    pub fn to_domain(&self, host: &Domain, pad_to_len: usize) -> Result<Domain, String> {
        let mut parts = Vec::new();
        parts.push(format!("f{}", self.encoding));
        parts.push(format!("{}", self.len));
        for x in &[self.bias, self.coefficient, self.modulus] {
            parts.push(format!("{}", *x));
        }
        let mut total_bytes = host.parts().iter().chain((&parts).into_iter())
            .map(|x| x.len() + 1).sum::<usize>() + 1;
        if total_bytes % 2 != pad_to_len % 2 {
            parts.push(String::from("xx"));
            total_bytes += 3;
        }
        while total_bytes < pad_to_len {
            parts.push(String::from("x"));
            total_bytes += 2;
        }
        if total_bytes > pad_to_len {
            Err(String::from("target length is too short"))
        } else {
            parts.extend(host.parts().to_vec());
            Domain::from_parts(parts)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_query_to_domain() {
        let query = DownloadGenQuery{
            encoding: String::from("raw"),
            len: 100,
            bias: 123,
            coefficient: 13,
            modulus: 178
        };
        assert_eq!(query.to_domain(&("fo.com".parse().unwrap()), 28).unwrap(),
            "fraw.100.123.13.178.fo.com".parse().unwrap());
        assert_eq!(query.to_domain(&("fo.com".parse().unwrap()), 30).unwrap(),
            "fraw.100.123.13.178.x.fo.com".parse().unwrap());
        assert_eq!(query.to_domain(&("fo.com".parse().unwrap()), 31).unwrap(),
            "fraw.100.123.13.178.xx.fo.com".parse().unwrap());
        assert_eq!(query.to_domain(&("fo.com".parse().unwrap()), 33).unwrap(),
            "fraw.100.123.13.178.xx.x.fo.com".parse().unwrap());
        assert_eq!(query.to_domain(&("fo.bar.com".parse().unwrap()), 32).unwrap(),
            "fraw.100.123.13.178.fo.bar.com".parse().unwrap());
        assert_eq!(query.to_domain(&("fo.bar.com".parse().unwrap()), 34).unwrap(),
            "fraw.100.123.13.178.x.fo.bar.com".parse().unwrap());
        assert!(query.to_domain(&("fo.bar.com".parse().unwrap()), 10).is_err());
        assert!(query.to_domain(&("fo.bar.com".parse().unwrap()), 33).is_err());
    }
}
