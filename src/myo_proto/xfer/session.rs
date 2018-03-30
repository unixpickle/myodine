use conn::TcpChunker;
use super::{Packet, WwrState};

/// Feed an incoming packet into a WWR state machine and a TCP socket.
///
/// Automatically deals with backpressure from the TCP socket.
///
/// Returns the number of bytes written to the connection.
pub fn handle_packet_in(packet: Packet, state: &mut WwrState, conn: &mut TcpChunker) -> usize {
    state.handle_ack(&packet.ack);
    if conn.can_send() && packet.chunk.is_some() {
        let mut buffer = Vec::new();
        let mut finished = false;
        for chunk in state.handle_chunk(packet.chunk.unwrap()) {
            if chunk.data.len() == 0 {
                finished = true;
                // Data past EOF is meaningless.
                break;
            } else {
                buffer.extend(chunk.data);
            }
        }
        let len = buffer.len();
        if len > 0 {
            conn.send(buffer);
        }
        if finished {
            conn.send_finished();
        }
        len
    } else {
        0
    }
}

/// Feed data from a TCP connection into a WWR state machine.
///
/// Produces the next packet to send on behalf of the WWR state.
///
/// Returns the number of bytes read from the connection.
pub fn next_packet_out(state: &mut WwrState, conn: &mut TcpChunker) -> (Packet, usize) {
    let mut bytes = 0;
    while state.send_buffer_space() > 0 {
        if let Some(data) = conn.recv() {
            if data.len() > 0 {
                bytes += data.len();
                state.push_send_buffer(data);
            } else {
                state.push_eof();
            }
        } else {
            break;
        }
    }
    (Packet{
        ack: state.next_send_ack(),
        chunk: state.next_send_chunk()
    }, bytes)
}
