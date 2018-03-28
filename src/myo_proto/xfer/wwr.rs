use std::num::Wrapping;

use super::{Ack, Chunk};

/// A finite state machine representing an endpoint's view of a WWR session.
pub struct WwrState {
    in_win_size: u16,
    in_win_start: u32,
    in_received: Vec<Chunk>,
    in_eof: bool,

    out_win_size: u16,
    out_next_seq: u32,
    out_win_start: u32,
    out_pending: Vec<Chunk>,
    out_round_robin: usize,
    out_eof: bool
}

impl WwrState {
    /// Create a `WwrState` given some initial conditions.
    ///
    /// # Arguments
    ///
    /// * `in_win_size` - The other end's outgoing window size.
    /// * `out_win_size` - Our outgoing window size.
    /// * `seq_start` - The initial sequence number for both directions.
    pub fn new(in_win_size: u16, out_win_size: u16, seq_start: u32) -> WwrState {
        WwrState{
            in_win_size: in_win_size,
            in_win_start: seq_start,
            in_received: Vec::new(),
            in_eof: false,

            out_win_size: out_win_size,
            out_next_seq: seq_start,
            out_win_start: seq_start,
            out_pending: Vec::new(),
            out_round_robin: 0,
            out_eof: false
        }
    }

    /// Check if both the incoming and outgoing streams have EOF'd.
    pub fn is_done(&self) -> bool {
        self.in_eof && self.out_eof
    }

    /// Get the current acknowledgement packet.
    pub fn next_send_ack(&self) -> Ack {
        let mut bit_mask = Vec::new();
        for _ in 0..(self.in_win_size - 1) {
            bit_mask.push(false);
        }
        for chunk in &self.in_received {
            let offset = (Wrapping(chunk.seq) - Wrapping(self.in_win_start)).0 - 1;
            assert!(offset < self.in_win_size as u32);
            bit_mask[offset as usize] = true;
        }
        Ack{window_start: self.in_win_start, window_mask: bit_mask}
    }

    /// Get a chunk to send in the next packet.
    ///
    /// This should only be called once per packet, since it cycles through
    /// the unacknowledged chunks in order to prevent starvation.
    ///
    /// If there are no chunks to send, this returns None.
    pub fn next_send_chunk(&mut self) -> Option<Chunk> {
        if self.out_pending.is_empty() {
            return None;
        }
        if self.out_round_robin >= self.out_pending.len() {
            self.out_round_robin = 0;
        }
        let chunk = self.out_pending[self.out_round_robin].clone();
        self.out_round_robin += 1;
        Some(chunk)
    }

    /// Get the number of chunks that can be pushed by `push_send_buffer`.
    pub fn send_buffer_space(&self) -> usize {
        let win_used = (Wrapping(self.out_next_seq) - Wrapping(self.out_win_start)).0;
        assert!((win_used as usize) <= (self.out_win_size as usize));
        (self.out_win_size as usize) - (win_used as usize)
    }

    /// Add an outgoing chunk to the end of the outgoing data stream.
    ///
    /// You should check `send_buffer_space` before calling this.
    /// You should not call this after calling `push_eof`.
    /// You should not pass an empty chunk.
    pub fn push_send_buffer(&mut self, data: Vec<u8>) {
        assert!(!self.out_eof);
        assert!(self.send_buffer_space() > 0);
        let chunk = Chunk{seq: self.out_next_seq, data: data};
        self.out_next_seq = (Wrapping(self.out_next_seq) + Wrapping(1)).0;
        self.out_pending.push(chunk);
    }

    /// Push an EOF to the end of the outgoing data stream.
    ///
    /// You should check `send_buffer_space` before calling this.
    /// You may call this multiple times; it is idempotent.
    pub fn push_eof(&mut self) {
        if self.out_eof {
            return;
        }
        self.push_send_buffer(Vec::new());
        self.out_eof = true;
    }

    /// Handle an acknowledgement from the remote end.
    pub fn handle_ack(&mut self, ack: &Ack) {
        if ack.window_start == self.out_next_seq {
            self.out_pending.clear();
            self.out_win_start = self.out_next_seq;
            return;
        }
        let residual = (Wrapping(ack.window_start) - Wrapping(self.out_win_start)).0;
        if residual > self.out_win_size as u32 {
            // This is a stale ACK.
            return;
        }
        for i in 0..residual {
            let residual_seq = (Wrapping(self.out_win_start) + Wrapping(i)).0;
            self.remove_out_seq(residual_seq);
        }
        self.out_win_start = ack.window_start;
        for (i, b) in (&ack.window_mask).into_iter().enumerate() {
            if *b {
                self.remove_out_seq((Wrapping(ack.window_start) + Wrapping(i as u32) +
                    Wrapping(1)).0);
            }
        }
    }

    /// Handle an incoming chunk from the remote end.
    ///
    /// Returns all of the chunks which can now be processed.
    /// The returned chunks are guaranteed to be in order, starting at the
    /// beginning of the current incoming window.
    ///
    /// If an empty chunk is included in the result, it is the last chunk and
    /// signals an EOF.
    pub fn handle_chunk(&mut self, chunk: Chunk) -> Vec<Chunk> {
        if self.in_eof {
            return Vec::new();
        }

        let chunk_offset = (Wrapping(chunk.seq) - Wrapping(self.in_win_start)).0;
        if chunk_offset >= self.in_win_size as u32 {
            // Stale chunk or some kind of premature chunk.
            return Vec::new();
        }
        if (&self.in_received).into_iter().any(|x| x.seq == chunk.seq) {
            return Vec::new();
        }
        self.in_received.push(chunk);

        let mut result = Vec::new();
        let mut got_chunk = true;
        while got_chunk {
            got_chunk = false;
            for i in 0..self.in_received.len() {
                if self.in_received[i].seq == self.in_win_start {
                    let chunk = self.in_received.swap_remove(i);
                    let is_eof = chunk.data.len() == 0;
                    result.push(chunk);
                    self.in_win_start += 1;
                    got_chunk = true;
                    if is_eof {
                        self.in_eof = true;
                        return result;
                    }
                    break;
                }
            }
        }
        result
    }

    fn remove_out_seq(&mut self, seq: u32) {
        for i in (0..self.out_pending.len()).into_iter().rev() {
            if self.out_pending[i].seq == seq {
                self.out_pending.remove(i);
                if self.out_round_robin > i {
                    self.out_round_robin -= 1;
                }
                return;
            }
        }
    }
}
