use std::fmt::Write;

use dns_proto::domain::Domain;
use dns_proto::message::Message;

pub fn is_api_query(m: &Message, prefix_char: char) -> bool {
    let is_query = !m.header.is_response &&
        m.questions.len() == 1 &&
        m.answers.len() == 0 &&
        m.authorities.len() == 0 &&
        m.additional.len() == 0;
    if is_query {
        let domain = &m.questions[0].domain;
        if domain.parts().len() > 0 {
            let first = &domain.parts()[0];
            return domain_part_lowercase(first).chars().next().unwrap() == prefix_char;
        }
    }
    return false;
}

pub fn domain_ends_with(domain: &Domain, suffix: &Domain) -> bool {
    if domain.parts().len() < suffix.parts().len() {
        return false;
    }
    let offset = domain.parts().len() - suffix.parts().len();
    for i in 0..suffix.parts().len() {
        if !domain_part_equal(&suffix.parts()[i], &domain.parts()[i + offset]) {
            return false;
        }
    }
    true
}

pub fn domain_part_equal(x: &str, y: &str) -> bool {
    return domain_part_lowercase(x) == domain_part_lowercase(y);
}

pub fn domain_part_lowercase(x: &str) -> String {
    let mut res = String::new();
    for ch in x.as_bytes() {
        if *ch >= ('A' as u8) && *ch <= ('Z' as u8) {
            res.write_char(((*ch - ('A' as u8)) + ('a' as u8)) as char)
        } else {
            res.write_char(*ch as char)
        }.unwrap();
    }
    res
}
