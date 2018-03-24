use std::fmt::Write;

use dns_proto::domain::Domain;

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
