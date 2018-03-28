use dns_proto::Message;
use myo_proto::util::is_api_query;

/// Check if a DNS message is a transfer query, and get the session ID if so.
pub fn xfer_query_session_id(query: &Message) -> Option<u16> {
    if !is_api_query(query, 't') && !is_api_query(query, 'p') {
        return None;
    }
    let part: String = query.questions[0].domain.parts()[0].chars().skip(1).collect();
    return part.parse().ok()
}
