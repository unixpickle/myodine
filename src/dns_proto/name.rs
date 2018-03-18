use std::fmt::{Display, Error, Formatter};
use std::str::FromStr;

use dns_proto::decoding::{Decoder, DecPacket};
use dns_proto::encoding::{Encoder, EncPacket};

#[derive(Clone, PartialEq, Eq, Debug)]
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

impl Decoder for Domain {
    fn dns_decode(packet: &mut DecPacket) -> Result<Domain, String> {
        let mut parts = Vec::<String>::new();
        loop {
            let size = u8::dns_decode(packet)?;
            if size & 0xc0 == 0xc0 {
                let addr_lower = u8::dns_decode(packet)?;
                let addr = (((size & 0x3f) as usize) << 8) | (addr_lower as usize);
                let mut seeked = packet.seek(addr, packet.current_offset() - 2)?;
                let pointer_domain = Domain::dns_decode(&mut seeked)?;
                for part in pointer_domain.0 {
                    parts.push(part);
                }
                return Domain::from_parts(parts);
            } else if size & 0xc0 != 0 {
                return Err(String::from("invalid label length field"))
            } else if size == 0 {
                return Domain::from_parts(parts);
            } else {
                match String::from_utf8(packet.read_bytes(size as usize)?) {
                    Ok(s) => parts.push(s),
                    Err(_) => return Err(String::from("invalid UTF-8 label"))
                }
            }
        }
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

    #[test]
    fn valid_pointer() {
        let data = vec![
            0u8, 0u8, 3u8, 'c' as u8, 'o' as u8, 'm' as u8,
            0u8, 1u8, 2u8, // filler, for no good reason
            2u8, 'a' as u8, 'b' as u8, 0xc0u8, 2u8
        ];
        let mut dec_packet = DecPacket::new(data).seek(9, 14).unwrap();
        let value = Domain::dns_decode(&mut dec_packet).unwrap();
        assert_eq!(value, "ab.com".parse().unwrap());
    }

    #[test]
    fn invalid_pointers() {
        let datas = vec![
            vec![0xc0u8, 0u8],
            vec![0xc0u8, 10u8],
            vec![8u8, 0u8]
        ];
        for data in datas {
            let mut packet = DecPacket::new(data);
            assert!(Domain::dns_decode(&mut packet).is_err());
        }
    }
}
