use std::fmt::Write;

use dns_proto::domain::Domain;

use super::util::domain_ends_with;

pub trait NameCode {
    fn encode_parts(&self, api_flag: char, data: &[u8]) -> Result<Vec<String>, String>;
    fn decode_parts(&self, parts: &[String]) -> Result<(char, Vec<u8>), String>;

    fn encode_domain(&self, api_flag: char, data: &[u8], host: &Domain) -> Result<Domain, String> {
        let mut parts = self.encode_parts(api_flag, data)?;
        for part in host.parts() {
            parts.push(part.clone());
        }
        Domain::from_parts(parts)
    }

    fn decode_domain(&self, name: &Domain, host: &Domain) -> Result<(char, Vec<u8>), String> {
        if !domain_ends_with(name, host) {
            Err(String::from("incorrect host domain"))
        } else if name.parts().len() == host.parts().len() {
            Err(String::from("no data in domain"))
        } else {
            let all_parts = name.parts().to_vec();
            self.decode_parts(&all_parts[0..(name.parts().len() - host.parts().len())])
        }
    }
}

pub fn get_name_code(name: &str) -> Option<Box<NameCode>> {
    match name {
        "b16" => Some(Box::new(HexNameCode{})),
        _ => None
    }
}

pub struct HexNameCode;

impl NameCode for HexNameCode {
    fn encode_parts(&self, api_flag: char, data: &[u8]) -> Result<Vec<String>, String> {
        let mut labels = Vec::new();
        let mut cur_label = format!("{}", api_flag);
        assert!(cur_label.is_ascii());
        for ch in data {
            if cur_label.len() == 0 {
                cur_label.write_char('h').unwrap();
            }
            write!(cur_label, "{:02x}", *ch).unwrap();
            if cur_label.len() + 2 > 63 {
                labels.push(cur_label);
                cur_label = String::new();
            }
        }
        if cur_label.len() > 0 {
            labels.push(cur_label);
        }
        Ok(labels)
    }

    fn decode_parts(&self, parts: &[String]) -> Result<(char, Vec<u8>), String> {
        let api_flag = parts[0].chars().next().unwrap();
        let mut data = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let label_bytes = part.as_bytes();
            if label_bytes.len() % 2 != 1 {
                return Err(String::from("invalid label length"));
            }
            if i > 0 && label_bytes[0] != 'h' as u8 {
                return Err(String::from("invalid first character"));
            }
            for i in 0..(label_bytes.len() / 2) {
                let (c1, c2) = (label_bytes[1 + i*2] as char, label_bytes[i*2 + 2] as char);
                if let Ok(res) = u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                    data.push(res);
                } else {
                    return Err(format!("invalid hex byte: {}{}", c1, c2));
                }
            }
        }
        Ok((api_flag, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_decode_short() {
        let root: Domain = "hello.com".parse().unwrap();
        let api_flag = 't';
        let code = HexNameCode{};
        let encoded = code.encode_domain(api_flag, &vec![0u8, 1u8, 2u8, 52u8], &root).unwrap();
        assert_eq!(encoded, "t00010234.hello.com".parse().unwrap());
        let (flag_out, decoded) = code.decode_domain(&encoded, &root).unwrap();
        assert_eq!(flag_out, api_flag);
        assert_eq!(decoded, vec![0u8, 1u8, 2u8, 52u8]);
    }

    #[test]
    fn hex_encode_decode_long() {
        let root: Domain = "foo.apple.com".parse().unwrap();
        let api_flag = 't';
        let code = HexNameCode{};
        let data = vec![0x23u8, 0x49u8, 0x75u8, 0xCEu8, 0x6Bu8, 0x0Cu8, 0x71u8, 0x7Bu8,
                        0x8Cu8, 0x1Cu8, 0x4Du8, 0x4Du8, 0xCCu8, 0x25u8, 0x9Cu8, 0x0Fu8,
                        0x00u8, 0xEEu8, 0xFFu8, 0x05u8, 0x7Fu8, 0x7Eu8, 0xB4u8, 0x20u8,
                        0xBBu8, 0x04u8, 0xE3u8, 0x85u8, 0x23u8, 0x63u8, 0x29u8, 0x99u8,
                        0xC4u8, 0x61u8, 0xB4u8, 0xF0u8, 0x0Eu8, 0xF0u8, 0x00u8, 0xA9u8,
                        0x26u8, 0xB6u8, 0x32u8, 0x37u8, 0xAAu8, 0xE5u8, 0xCCu8, 0x6Du8,
                        0x15u8, 0x08u8, 0xEAu8, 0xDDu8, 0x33u8, 0xADu8, 0xB1u8, 0x00u8,
                        0xEFu8, 0x01u8, 0x0Cu8, 0x71u8, 0xA2u8, 0x85u8];
        let encoded = code.encode_domain(api_flag, &data, &root).unwrap();
        assert_eq!(encoded, format!("{}.{}.foo.apple.com",
            "t234975ce6b0c717b8c1c4d4dcc259c0f00eeff057f7eb420bb04e385236329",
            "h99c461b4f00ef000a926b63237aae5cc6d1508eadd33adb100ef010c71a285").parse().unwrap());
        let (flag_out, decoded) = code.decode_domain(&encoded, &root).unwrap();
        assert_eq!(flag_out, api_flag);
        assert_eq!(decoded, data);
    }
}
