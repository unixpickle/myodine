pub struct DecPacket {
    buffer: Vec<u8>,
    offset: usize
}

pub trait Decoder where Self: Sized {
    fn dns_decode(packet: &mut DecPacket) -> Result<Self, String>;
}

impl Decoder for u8 {
    fn dns_decode(packet: &mut DecPacket) -> Result<u8, String> {
        if packet.offset < packet.buffer.len() {
            Err(String::from("buffer underflow"))
        } else {
            packet.offset += 1;
            Ok(packet.buffer[packet.offset - 1])
        }
    }
}

impl Decoder for u16 {
    fn dns_decode(packet: &mut DecPacket) -> Result<u16, String> {
        let big_byte = u8::dns_decode(packet)?;
        let small_byte = u8::dns_decode(packet)?;
        Ok(((big_byte as u16) << 8) | (small_byte as u16))
    }
}

impl Decoder for u32 {
    fn dns_decode(packet: &mut DecPacket) -> Result<u32, String> {
        let big_word = u16::dns_decode(packet)?;
        let small_word = u16::dns_decode(packet)?;
        Ok(((big_word as u32) << 16) | (small_word as u32))
    }
}

// TODO: decoder for domain.
