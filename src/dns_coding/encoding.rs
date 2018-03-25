use std::iter::IntoIterator;
use std::mem::size_of;

pub fn dns_encode<T: Encoder>(x: &T) -> Result<Vec<u8>, String> {
    let mut packet = EncPacket::new();
    x.dns_encode(&mut packet)?;
    Ok(packet.0)
}

pub struct EncPacket(Vec<u8>);

impl EncPacket {
    pub fn new() -> EncPacket {
        EncPacket(Vec::new())
    }

    pub fn encode_with_length<F>(&mut self, f: F) -> Result<(), String>
        where F: FnOnce(&mut EncPacket) -> Result<(), String>
    {
        let offset = self.0.len();
        0u16.dns_encode(self)?;

        f(self)?;

        let delta_length = self.0.len() - offset - 2;
        if delta_length > 0xffff {
            Err(String::from("length field overflow"))
        } else {
            self.0[offset] = (delta_length >> 8) as u8;
            self.0[offset + 1] = (delta_length & 0xff) as u8;
            Ok(())
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.0
    }
}

pub trait Encoder {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String>;
}

impl Encoder for u8 {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        packet.0.push(*self);
        Ok(())
    }
}

impl Encoder for u16 {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        packet.0.push((*self >> 8) as u8);
        packet.0.push((*self & 0xff) as u8);
        Ok(())
    }
}

impl Encoder for u32 {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        packet.0.push((*self >> 24) as u8);
        packet.0.push(((*self >> 16) & 0xff) as u8);
        packet.0.push(((*self >> 8) & 0xff) as u8);
        packet.0.push((*self & 0xff) as u8);
        Ok(())
    }
}

impl Encoder for u64 {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        for i in 0..8 {
            packet.0.push((*self >> (56 - i * 8)) as u8);
        }
        Ok(())
    }
}

impl<T: Encoder> Encoder for Vec<T> {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        for item in self.into_iter() {
            item.dns_encode(packet)?;
        }
        Ok(())
    }
}

pub struct BitWriter {
    value: usize,
    bits_used: usize
}

impl BitWriter {
    pub fn new() -> BitWriter {
        BitWriter{
            value: 0,
            bits_used: 0
        }
    }

    pub fn write_bit(&mut self, bit: bool) {
        self.bits_used += 1;
        self.value <<= 1;
        if bit {
            self.value |= 1;
        }
    }

    pub fn write_bits(&mut self, value: usize, num_bits: usize) {
        for i in 0..num_bits {
            self.write_bit(value & (1 << (num_bits - (i + 1))) != 0);
        }
    }

    pub fn fits<T>(&self) -> bool {
        self.bits_used == size_of::<T>() * 8
    }

    pub fn value(&self) -> usize {
        self.value
    }
}

macro_rules! encode_all {
    ( $dest:expr ) => { Ok(()) };
    ( $dest:expr, $first:expr $(, $rest:expr )* ) => {
        {
            let res = $first.dns_encode($dest);
            if !res.is_ok() {
                res
            } else {
                encode_all!($dest $(,$rest)*)
            }
        }
    }
}
