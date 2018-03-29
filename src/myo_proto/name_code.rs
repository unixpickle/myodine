use std::fmt::Write;

use dns_proto::Domain;

use super::util::domain_ends_with;

/// Lookup the NameCode for the given identifier.
pub fn get_name_code(name: &str) -> Option<Box<NameCode>> {
    match name {
        "b16" => Some(Box::new(HexNameCode{})),
        _ => None
    }
}

/// A method of encoding raw data in DNS names.
pub trait NameCode {
    /// Encode the raw data as domain name labels.
    fn encode_parts(&self, data: &[u8]) -> Result<Vec<String>, String>;

    /// Decode the raw data from domain name labels.
    fn decode_parts(&self, parts: &[String]) -> Result<Vec<u8>, String>;

    /// Encode the data into the full `Domain` for a transfer query.
    ///
    /// # Arguments
    ///
    /// * `api_flag` - A character that specifies the kind of transfer packet.
    /// * `sess_id` - The session ID corresponding to the transfer packet.
    /// * `data` - The raw data to encode.
    /// * `host` - The root domain name of the server.
    fn encode_domain(
        &self,
        api_flag: char,
        sess_id: u16,
        data: &[u8],
        host: &Domain
    ) -> Result<Domain, String> {
        let mut parts = Vec::new();
        parts.push(format!("{}{}", api_flag, sess_id));
        parts.extend(self.encode_parts(data)?);
        parts.extend(host.parts().to_vec());
        Domain::from_parts(parts)
    }

    /// Decode the data from a transfer query's domain name.
    ///
    /// # Arguments
    ///
    /// * `name` - The full query domain name.
    /// * `host` - The root domain name of the server.
    ///
    /// # Returns
    ///
    /// A tuple of the form (api_code, session_id, data).
    fn decode_domain(&self, name: &Domain, host: &Domain) -> Result<(char, u16, Vec<u8>), String> {
        if !domain_ends_with(name, host) {
            Err("incorrect host domain".to_owned())
        } else if name.parts().len() < host.parts().len() + 2 {
            Err("not enough data".to_owned())
        } else {
            let mut all_parts = name.parts().to_vec();
            let sess_part = all_parts.remove(0);
            let api_code = sess_part.chars().next().unwrap();
            let sess_id = sess_part.chars().skip(1).collect::<String>().parse();
            if sess_id.is_err() {
                return Err("invalid session ID".to_owned());
            }
            Ok((api_code, sess_id.unwrap(),
                self.decode_parts(&all_parts[0..(all_parts.len() - host.parts().len())])?))
        }
    }
}

/// A NameCode that uses hexadecimal.
pub struct HexNameCode;

impl NameCode for HexNameCode {
    fn encode_parts(&self, data: &[u8]) -> Result<Vec<String>, String> {
        let mut encoded = String::new();
        for ch in data {
            write!(encoded, "{:02x}", *ch).unwrap();
        }
        Ok(split_labels(encoded))
    }

    fn decode_parts(&self, parts: &[String]) -> Result<Vec<u8>, String> {
        let mut hex_data = String::new();
        hex_data.extend(parts.iter().map(|x| x as &str));
        let bytes = hex_data.as_bytes();
        if bytes.len() % 2 != 0 {
            return Err("invalid data length".to_owned());
        }
        let mut data = Vec::new();
        for i in 0..(bytes.len() / 2) {
            let (c1, c2) = (bytes[i*2] as char, bytes[i*2 + 1] as char);
            if let Ok(res) = u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                data.push(res);
            } else {
                return Err(format!("invalid hex byte: {}{}", c1, c2));
            }
        }
        Ok(data)
    }
}

fn split_labels(all_data: String) -> Vec<String> {
    let mut res = Vec::new();
    let mut cur_data = all_data;
    while cur_data.len() > 63 {
        res.push(cur_data.chars().take(63).collect());
        cur_data = cur_data.chars().skip(63).collect();
    }
    res.push(cur_data);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_decode_short() {
        let root: Domain = "hello.com".parse().unwrap();
        let api_flag = 't';
        let sess_id = 13u16;
        let code = HexNameCode{};
        let encoded = code.encode_domain(api_flag, sess_id, &vec![0u8, 1u8, 2u8, 52u8],
            &root).unwrap();
        assert_eq!(encoded, "t13.00010234.hello.com".parse().unwrap());
        let (flag_out, id_out, decoded) = code.decode_domain(&encoded, &root).unwrap();
        assert_eq!(flag_out, api_flag);
        assert_eq!(id_out, sess_id);
        assert_eq!(decoded, vec![0u8, 1u8, 2u8, 52u8]);
    }

    #[test]
    fn hex_encode_decode_long() {
        let root: Domain = "foo.apple.com".parse().unwrap();
        let api_flag = 't';
        let sess_id = 13u16;
        let code = HexNameCode{};
        let data = vec![0x23u8, 0x49u8, 0x75u8, 0xCEu8, 0x6Bu8, 0x0Cu8, 0x71u8, 0x7Bu8,
                        0x8Cu8, 0x1Cu8, 0x4Du8, 0x4Du8, 0xCCu8, 0x25u8, 0x9Cu8, 0x0Fu8,
                        0x00u8, 0xEEu8, 0xFFu8, 0x05u8, 0x7Fu8, 0x7Eu8, 0xB4u8, 0x20u8,
                        0xBBu8, 0x04u8, 0xE3u8, 0x85u8, 0x23u8, 0x63u8, 0x29u8, 0x99u8,
                        0xC4u8, 0x61u8, 0xB4u8, 0xF0u8, 0x0Eu8, 0xF0u8, 0x00u8, 0xA9u8,
                        0x26u8, 0xB6u8, 0x32u8, 0x37u8, 0xAAu8, 0xE5u8, 0xCCu8, 0x6Du8,
                        0x15u8, 0x08u8, 0xEAu8, 0xDDu8, 0x33u8, 0xADu8, 0xB1u8, 0x00u8,
                        0xEFu8, 0x01u8, 0x0Cu8, 0x71u8, 0xA2u8, 0x85u8, 0xABu8];
        let encoded = code.encode_domain(api_flag, sess_id, &data, &root).unwrap();
        assert_eq!(encoded, format!("t13.{}.{}.foo.apple.com",
            "234975ce6b0c717b8c1c4d4dcc259c0f00eeff057f7eb420bb04e3852363299",
            "9c461b4f00ef000a926b63237aae5cc6d1508eadd33adb100ef010c71a285ab").parse().unwrap());
        let (flag_out, id_out, decoded) = code.decode_domain(&encoded, &root).unwrap();
        assert_eq!(flag_out, api_flag);
        assert_eq!(id_out, sess_id);
        assert_eq!(decoded, data);
    }
}
