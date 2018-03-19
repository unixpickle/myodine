use std::mem::size_of;

pub struct EncPacket(Vec<u8>);

pub trait Encoder {
    fn dns_encode(&self, packet: &mut EncPacket);
}

impl Encoder for u8 {
    fn dns_encode(&self, packet: &mut EncPacket) {
        packet.0.push(*self);
    }
}

impl Encoder for u16 {
    fn dns_encode(&self, packet: &mut EncPacket) {
        packet.0.push((*self >> 8) as u8);
        packet.0.push((*self & 0xff) as u8);
    }
}

impl Encoder for u32 {
    fn dns_encode(&self, packet: &mut EncPacket) {
        packet.0.push((*self >> 24) as u8);
        packet.0.push(((*self >> 16) & 0xff) as u8);
        packet.0.push(((*self >> 8) & 0xff) as u8);
        packet.0.push((*self & 0xff) as u8);
    }
}

impl<'a, T: Encoder> Encoder for &'a [T] {
    fn dns_encode(&self, packet: &mut EncPacket) {
        for x in *self {
            x.dns_encode(packet);
        }
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

    pub fn pack<T: From<usize> + Sized>(&self) -> Option<T> {
        if self.bits_used == size_of::<T>() {
            Some(From::from(self.value))
        } else {
            None
        }
    }
}
