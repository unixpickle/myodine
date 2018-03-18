use std::fmt::{Display, Error, Formatter};
use std::str::FromStr;

use dns_proto::encoding::{Encoder, EncPacket};

pub struct Domain(Vec<String>);

impl Domain {
    pub fn from_parts(labels: Vec<String>) -> Result<Domain, String> {
        let mut total_len = 1usize;
        for label in &labels {
            if label.len() == 0 {
                return Err(format!("empty domain name label"));
            } else if !label.is_ascii() {
                return Err(format!("domain label is not ASCII: {}", label));
            } else if label.len() > 63 {
                return Err(format!("domain label is too long: {}", label));
            }
            total_len += label.len() + 1usize;
            let chars: Vec<char> = label.chars().collect();
            if !in_char_range('a', 'z', chars[0]) && !in_char_range('A', 'Z', chars[0]) {
                return Err(format!("domain label must start with a-zA-Z"));
            }
            if chars[chars.len() - 1] == '-' {
                return Err(format!("domain label may not end in -"));
            }
            for b in chars {
                if !in_char_range('a', 'z', b) && !in_char_range('A', 'Z', b) &&
                    !in_char_range('0', '9', b) && b != '-' {
                    return Err(format!("domain label may only contain a-zA-Z0-9-"));
                }
            }
        }
        if total_len > 255 {
            return Err(format!("domain name is too long"));
        }
        Ok(Domain(labels))
    }

    pub fn parts(&self) -> &[String] {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = String;

    fn from_str(s: &str) -> Result<Domain, String> {
        Domain::from_parts(s.split(".").map(|x| String::from(x)).collect())
    }
}

impl Display for Domain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for (i, x) in (&self.0).into_iter().enumerate() {
            if i != 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", x)?;
        }
        Ok(())
    }
}

impl Encoder for Domain {
    fn dns_encode(&self, packet: &mut EncPacket) {
        for part in self.parts() {
            let bytes = part.as_bytes();
            assert!(bytes.len() < 64);
            (bytes.len() as u8).dns_encode(packet);
            for b in bytes {
                b.dns_encode(packet);
            }
        }
        0u8.dns_encode(packet);
    }
}

fn in_char_range(start: char, end: char, ch: char) -> bool {
    ch >= start && ch <= end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_parse() {
        let domain: Domain = "zoo-1bar.Aol9.AOE".parse().unwrap();
        assert_eq!(vec![String::from("zoo-1bar"), String::from("Aol9"), String::from("AOE")],
            domain.0);
    }

    #[test]
    fn unsuccessful_parse() {
        let strs = vec![String::from("zoo-.google.com"), String::from("9foo.google.com"),
            "a".repeat(64), format!("{}.com", "aoeu.".repeat(50))];
        for domain in strs {
            assert!(Domain::from_str(&domain).is_err());
        }
    }

    #[test]
    fn display_domain() {
        let examples = vec!["zoo-1bar.Aol9.AOE", "play.google.com"];
        for s in examples {
            assert_eq!(s, format!("{}", Domain::from_str(&s).unwrap()));
        }
    }
}
