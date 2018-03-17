use std::str::FromStr;

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
            if in_char_range('a', 'z', chars[0]) && !in_char_range('A', 'Z', chars[0]) {
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
}

impl FromStr for Domain {
    type Err = String;

    fn from_str(s: &str) -> Result<Domain, String> {
        Domain::from_parts(s.split(".").map(|x| String::from(x)).collect())
    }
}

fn in_char_range(start: char, end: char, ch: char) -> bool {
    ch >= start && ch <= end
}
