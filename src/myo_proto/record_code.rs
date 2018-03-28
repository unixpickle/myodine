use dns_coding::{DecPacket, Decoder, EncPacket, Encoder};
use dns_proto::{RecordBody, RecordType};

/// Lookup the RecordCode for the given record type and code identifier.
pub fn get_record_code(record_type: RecordType, name: &str) -> Option<Box<RecordCode>> {
    match record_type {
        RecordType::TXT => {
            if name == "raw" {
                Some(Box::new(RawTxtCode{}))
            } else {
                None
            }
        }
        _ => None
    }
}

/// A method of encoding raw data in DNS records.
pub trait RecordCode {
    /// Encode the data into a record.
    fn encode_body(&self, data: &[u8]) -> Result<RecordBody, String>;

    /// Decode the data from a record.
    fn decode_body(&self, body: &RecordBody) -> Result<Vec<u8>, String>;
}

/// A RecordCode that puts raw data into TXT records.
pub struct RawTxtCode;

impl RecordCode for RawTxtCode {
    fn encode_body(&self, data: &[u8]) -> Result<RecordBody, String> {
        let mut result = EncPacket::new();
        let mut next_buf = Vec::new();
        for x in data.iter() {
            next_buf.push(*x);
            if next_buf.len() == 255 {
                255u8.dns_encode(&mut result)?;
                next_buf.dns_encode(&mut result)?;
                next_buf.clear();
            }
        }
        if next_buf.len() > 0 || result.data().len() == 0 {
            (next_buf.len() as u8).dns_encode(&mut result)?;
            next_buf.dns_encode(&mut result)?;
        }
        Ok(RecordBody::Unknown(result.data().clone()))
    }

    fn decode_body(&self, body: &RecordBody) -> Result<Vec<u8>, String> {
        if let &RecordBody::Unknown(ref data) = body {
            let mut packet = DecPacket::new(data.clone());
            let mut result = Vec::new();
            while packet.remaining() > 0 {
                let field_len = u8::dns_decode(&mut packet)?;
                result.extend(packet.decode_all::<u8>(field_len as usize)?);
            }
            Ok(result)
        } else {
            Err(String::from("unexpected record type"))
        }
    }
}
