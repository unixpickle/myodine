use myodine::dns_proto::message::Message;

pub enum Event {
    Response(usize, Message),
    ReadTimeout(usize),
    Error(String)
}
