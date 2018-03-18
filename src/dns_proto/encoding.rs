pub struct Encoded(Vec<u8>);

use dns_proto::name::Domain;

pub trait Encoder {
    fn dns_encode(&self, packet: &mut Encoded);
}

impl Encoder for u8 {
    fn dns_encode(&self, packet: &mut Encoded) {
        packet.0.push(*self);
    }
}

impl Encoder for u16 {
    fn dns_encode(&self, packet: &mut Encoded) {
        packet.0.push((*self >> 8) as u8);
        packet.0.push((*self & 0xff) as u8);
    }
}

impl Encoder for u32 {
    fn dns_encode(&self, packet: &mut Encoded) {
        packet.0.push((*self >> 24) as u8);
        packet.0.push(((*self >> 16) & 0xff) as u8);
        packet.0.push(((*self >> 8) & 0xff) as u8);
        packet.0.push((*self & 0xff) as u8);
    }
}

impl Encoder for Domain {
    fn dns_encode(&self, packet: &mut Encoded) {
        for part in self.parts() {
            let bytes = part.as_bytes();
            assert!(bytes.len() < 64);
            packet.0.push(bytes.len() as u8);
            for b in bytes {
                packet.0.push(*b);
            }
        }
        packet.0.push(0u8);
    }
}

impl<'a, T: Encoder> Encoder for &'a [T] {
    fn dns_encode(&self, packet: &mut Encoded) {
        for x in *self {
            x.dns_encode(packet);
        }
    }
}
