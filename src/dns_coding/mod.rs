#[macro_use]
pub mod encoding;

pub mod decoding;

pub use self::decoding::{DecPacket, Decoder, BitReader, dns_decode};
pub use self::encoding::{EncPacket, Encoder, BitWriter, dns_encode};
