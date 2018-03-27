extern crate rand;
use self::rand::thread_rng;
use self::rand::distributions::{Range, IndependentSample};

use dns_coding::{DecPacket, Decoder, EncPacket, Encoder};

#[derive(Clone, Debug)]
pub struct Ack {
    pub window_start: u32,
    pub window_mask: Vec<bool>
}

#[derive(Clone, Debug)]
pub struct Chunk {
    pub seq: u32,
    pub data: Vec<u8>
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub ack: Ack,
    pub chunk: Option<Chunk>
}

impl Ack {
    pub fn decode(packet: &mut DecPacket, window_size: u16) -> Result<Ack, String> {
        let window_start = Decoder::dns_decode(packet)?;
        let num_bits = (window_size as usize) * 8 - 1;
        let num_bytes = if num_bits % 8 != 0 {
            num_bits / 8 + 1
        } else {
            num_bits / 8
        };
        let mut bits = Vec::new();
        for byte in packet.read_bytes(num_bytes)? {
            for j in 0..8 {
                if bits.len() < num_bits {
                    bits.push(byte & (1 << (7 - j)) != 0);
                }
            }
        }
        Ok(Ack{window_start: window_start, window_mask: bits})
    }
}

impl Encoder for Ack {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        self.window_start.dns_encode(packet)?;
        let mut cur_byte = 0u8;
        for (i, b) in (&self.window_mask).into_iter().enumerate() {
            cur_byte = cur_byte << 1;
            if *b {
                cur_byte |= 1;
            }
            if i % 8 == 7 {
                cur_byte.dns_encode(packet)?;
                cur_byte = 0;
            }
        }
        if self.window_mask.len() % 8 != 0 {
            cur_byte <<= 8 - (self.window_mask.len() % 8);
            cur_byte.dns_encode(packet)?;
        }
        Ok(())
    }
}

impl Decoder for Chunk {
    fn dns_decode(packet: &mut DecPacket) -> Result<Chunk, String> {
        let seq = Decoder::dns_decode(packet)?;
        let remaining = packet.remaining();
        let data = packet.read_bytes(remaining)?;
        Ok(Chunk{seq: seq, data: data})
    }
}

impl Encoder for Chunk {
    fn dns_encode(&self, packet: &mut EncPacket) -> Result<(), String> {
        self.seq.dns_encode(packet)?;
        self.data.dns_encode(packet)
    }
}

impl Packet {
    pub fn encode_query(&self) -> Result<(char, Vec<u8>), String> {
        let mut enc_packet = EncPacket::new();
        self.ack.dns_encode(&mut enc_packet)?;
        let api_code = if let &Some(ref chunk) = &self.chunk {
            chunk.dns_encode(&mut enc_packet)?;
            't'
        } else {
            let mut rng = thread_rng();
            let range = Range::new(0u64, 0xffffffffffffffffu64);
            range.ind_sample(&mut rng).dns_encode(&mut enc_packet)?;
            'p'
        };
        Ok((api_code, enc_packet.data().clone()))
    }

    pub fn decode_query(data: &[u8], window_size: u16, api_code: char) -> Result<Packet, String> {
        let mut packet = DecPacket::new(data.to_vec());
        if api_code != 't' && api_code != 'p' {
            return Err(format!("unknown API code: {}", api_code));
        }
        let ack = Ack::decode(&mut packet, window_size)?;
        Ok(Packet{
            ack: ack,
            chunk: if api_code == 't' {
                Some(Decoder::dns_decode(&mut packet)?)
            } else {
                None
            }
        })
    }

    pub fn encode_response(&self) -> Result<Vec<u8>, String> {
        let mut packet = EncPacket::new();
        self.ack.dns_encode(&mut packet)?;
        if let &Some(ref chunk) = &self.chunk {
            chunk.dns_encode(&mut packet)?;
        }
        Ok(packet.data().clone())
    }

    pub fn decode_response(data: &[u8], window_size: u16) -> Result<Packet, String> {
        let mut packet = DecPacket::new(data.to_vec());
        let ack = Ack::decode(&mut packet, window_size)?;
        Ok(Packet{
            ack: ack,
            chunk: if packet.remaining() > 0 {
                Some(Decoder::dns_decode(&mut packet)?)
            } else {
                None
            }
        })
    }
}
