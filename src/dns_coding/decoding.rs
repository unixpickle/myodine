/// Decode a packet using a Decoder implementation.
pub fn dns_decode<T: Decoder>(data: Vec<u8>) -> Result<T, String> {
    let mut dec = DecPacket::new(data);
    T::dns_decode(&mut dec)
}

/// A buffer that represents a packet and the current offset within it.
pub struct DecPacket {
    buffer: Vec<u8>,
    offset: usize
}

impl DecPacket {
    /// Create a new `DecPacket` with the given data, seeked to the start.
    pub fn new(data: Vec<u8>) -> DecPacket {
        DecPacket{
            buffer: data,
            offset: 0
        }
    }

    /// Get the current seek offset.
    pub fn current_offset(&self) -> usize {
        self.offset
    }

    /// Generate a new `DecPacket` that is like the current one, but cut short and
    /// seeked to the given offset.
    ///
    /// Fails if a parameter is out of bounds.
    pub fn seek(&self, new_offset: usize, new_size: usize) -> Result<DecPacket, String> {
        if new_offset >= new_size || new_size > self.buffer.len() {
            return Err("seek out of bounds".to_owned());
        }
        let mut res = Vec::new();
        for x in &self.buffer[0..new_size] {
            res.push(*x);
        }
        Ok(DecPacket{
            buffer: res,
            offset: new_offset,
        })
    }

    /// Get the bytes remaining in the buffer.
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.offset
    }

    /// Read the given number of bytes from the current position.
    pub fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, String> {
        let mut res = Vec::new();
        for _ in 0..num_bytes {
            res.push(u8::dns_decode(self)?);
        }
        Ok(res)
    }

    /// Decode a sequence of homogeneously-typed objects.
    pub fn decode_all<T: Decoder>(&mut self, num_items: usize) -> Result<Vec<T>, String> {
        let mut res = Vec::new();
        for _ in 0..num_items {
            res.push(T::dns_decode(self)?);
        }
        Ok(res)
    }

    /// Decode a piece of data that is preceded by a 16-bit length field.
    ///
    /// Passes the length to `f`, and ensures that `f` reads exactly the correct
    /// number of bytes.
    pub fn decode_with_length<F, T>(&mut self, f: F) -> Result<T, String>
        where F: FnOnce(&mut DecPacket, usize) -> Result<T, String>
    {
        let len = u16::dns_decode(self)? as usize;
        let offset = self.offset;
        let result = f(self, len)?;
        if self.offset < len || self.offset - len != offset {
            Err("incorrect length field".to_owned())
        } else {
            Ok(result)
        }
    }
}

/// A type that can decode itself from a `DecPacket`.
pub trait Decoder where Self: Sized {
    fn dns_decode(packet: &mut DecPacket) -> Result<Self, String>;
}

impl Decoder for u8 {
    fn dns_decode(packet: &mut DecPacket) -> Result<u8, String> {
        if packet.offset >= packet.buffer.len() {
            Err("buffer underflow".to_owned())
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

impl Decoder for u64 {
    fn dns_decode(packet: &mut DecPacket) -> Result<u64, String> {
        let big_word = u32::dns_decode(packet)?;
        let small_word = u32::dns_decode(packet)?;
        Ok(((big_word as u64) << 32) | (small_word as u64))
    }
}

/// An API for reading bit-fields.
pub struct BitReader {
    value: usize,
    bits_remaining: usize
}

impl BitReader {
    /// Create a bit reader using a numeric value and the initial number of
    /// bits stored in that value.
    pub fn new(value: usize, bits: usize) -> BitReader {
        BitReader{
            value: value,
            bits_remaining: bits
        }
    }

    /// Read the next bit, starting from the MSB.
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.bits_remaining == 0 {
            None
        } else {
            self.bits_remaining -= 1;
            let result = (self.value & (1 << self.bits_remaining)) != 0;
            Some(result)
        }
    }

    /// Read a sequence of bits and pack it back into an integer.
    pub fn read_bits(&mut self, num_bits: usize) -> Option<usize> {
        let mut result = 0usize;
        for _ in 0..num_bits {
            result <<= 1;
            if self.read_bit()? {
                result |= 1;
            }
        }
        Some(result)
    }
}
