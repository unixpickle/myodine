use std::net::Ipv4Addr;

use dns_proto::{Domain, Message, Record, RecordHeader, RecordType, RecordBody};

use super::record_code::get_record_code;
use super::util::{domain_part_lowercase, is_api_query};

extern crate sha1;
use self::sha1::Sha1;

/// Check if a DNS message is a domain hash API call.
pub fn is_domain_hash_query(query: &Message) -> bool {
    is_discovery_query(query) && query.questions[0].record_type == RecordType::A
}

/// Check if a DNS message is a download generation API call.
pub fn is_download_gen_query(query: &Message) -> bool {
    is_discovery_query(query) && query.questions[0].record_type == RecordType::TXT
}

/// Produce a response message for a domain hash query.
pub fn domain_hash_response(query: &Message) -> Result<Message, String> {
    if !is_domain_hash_query(query) {
        return Err("not a domain hash query".to_owned());
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
        body: RecordBody::A(hash)
    });
    result.header.answer_count = 1;
    result.header.is_response = true;
    Ok(result)
}

/// Produce a response message for a download generation query.
pub fn download_gen_response(query: &Message) -> Result<Message, String> {
    if !is_download_gen_query(query) {
        return Err("not a download generation query".to_owned());
    }
    let question = &query.questions[0];
    let parsed_query = DownloadGenQuery::from_domain(&question.domain)?;
    let encoder = get_record_code(question.record_type, &parsed_query.encoding)
        .ok_or("no record code found".to_owned())?;
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
    result.header.is_response = true;
    Ok(result)
}

/// Generate the domain hash according to the myodine spec.
pub fn domain_hash(domain: &Domain) -> Ipv4Addr {
    let mut sh = Sha1::new();
    sh.update(format!("{}", domain).as_bytes());
    let data = sh.digest().bytes();
    Ipv4Addr::new(data[0], data[1], data[2], data[3])
}

/// The contents of a DownloadGenQuery.
#[derive(Debug)]
pub struct DownloadGenQuery {
    pub encoding: String,
    pub len: u16,
    pub bias: u8,
    pub coefficient: u8,
    pub modulus: u8
}

impl DownloadGenQuery {
    /// Decode a `DownloadGenQuery` from a requested domain.
    pub fn from_domain(domain: &Domain) -> Result<DownloadGenQuery, String> {
        if domain.parts().len() < 5 {
            return Err("not enough domain parts".to_owned());
        }
        let encoding = domain_part_lowercase(&domain.parts()[0]).chars().skip(1).collect();
        let len = domain.parts()[1].parse();
        let bias = domain.parts()[2].parse();
        let coefficient = domain.parts()[3].parse();
        let modulus = domain.parts()[4].parse();
        if len.is_err() || bias.is_err() || coefficient.is_err() || modulus.is_err() ||
            *modulus.as_ref().unwrap() < 2 {
            Err("invalid number in domain".to_owned())
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

    /// Generate the data requested by the query.
    pub fn generated_data(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..self.len {
            let value = ((i as u64) + (self.bias as u64)) * (self.coefficient as u64) %
                (self.modulus as u64);
            result.push(value as u8);
        }
        result
    }

    /// Encode the query to a domain name.
    ///
    /// # Arguments
    ///
    /// * `host` - The root domain name of the server.
    /// * `pad_to_len` - The total number of bytes for the encoded domain name
    ///   to consume. Maximum value is 255.
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
            parts.push("xx".to_owned());
            total_bytes += 3;
        }
        while total_bytes < pad_to_len {
            parts.push("x".to_owned());
            total_bytes += 2;
        }
        if total_bytes > pad_to_len {
            Err("target length is too short".to_owned())
        } else {
            parts.extend(host.parts().to_vec());
            Domain::from_parts(parts)
        }
    }
}

fn is_discovery_query(query: &Message) -> bool {
    is_api_query(query, 'f')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_query_to_domain() {
        let query = DownloadGenQuery{
            encoding: "raw".to_owned(),
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
