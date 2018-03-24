use dns_proto::message::Message;

use super::util::domain_part_lowercase;

pub fn is_discovery_query(query: &Message) -> bool {
    if query.header.is_response && query.questions.len() == 1 &&
        query.questions[0].domain.parts().len() > 0 {
        let first = &query.questions[0].domain.parts()[0];
        domain_part_lowercase(first).chars().next().unwrap() == 'f'
    } else {
        false
    }
}
