//! Types for representing DNS messages.

mod domain;
mod header;
mod record;
mod message;

pub use self::domain::Domain;
pub use self::header::{Header, Opcode, ResponseCode};
pub use self::message::{Message, Question};
pub use self::record::{Record, RecordBody, RecordClass, RecordHeader, RecordType, SOADetails};
