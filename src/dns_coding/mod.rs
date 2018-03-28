//! APIs for serializing binary data.

#[macro_use]
mod encoding;
mod decoding;

pub use self::decoding::{DecPacket, Decoder, BitReader, dns_decode};
pub use self::encoding::{EncPacket, Encoder, BitWriter, dns_encode};
