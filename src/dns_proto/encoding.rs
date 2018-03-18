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
