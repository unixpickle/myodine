use std::net::Ipv4Addr;

use dns_proto::message::Message;
use dns_proto::record::{Record, RecordHeader, RecordType, RecordBody};

use super::util::{domain_hash, domain_part_lowercase};

pub fn is_discovery_query(query: &Message) -> bool {
    if query.header.is_response &&
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

pub fn is_domain_hash_query(query: &Message) -> bool {
    is_discovery_query(query) &&
        query.questions[0].record_type == RecordType::A
}

pub fn domain_hash_result(query: &Message) -> Message {
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
        body: RecordBody::ARecord(Ipv4Addr::new(hash[0], hash[1], hash[2], hash[3]))
    });
    result.header.answer_count = 1;
    result
}
