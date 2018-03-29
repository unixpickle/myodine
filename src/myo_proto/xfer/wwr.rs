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

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::repeat;

    #[test]
    fn symmetric_single_window() {
        let (mut end1, mut end2) = (trivial_endpoint(), trivial_endpoint());
        for _ in 0..10 {
            basic_xfer(&mut end1, &mut end2);
        }
        basic_eof(&mut end1);
        basic_eof(&mut end2);
    }

    #[test]
    fn multi_window() {
        for i in 0..512 {
            let mut state = WwrState::new(15, 5, 0xfffffdff + i);
            for j in 1..15 {
                reverse_window_in(&mut state, j);
            }
            windowed_eof(&mut state);
        }
    }

    #[test]
    fn out_of_bounds_ack() {
        let mut state = WwrState::new(15, 5, 0xfffffffe);
        state.push_send_buffer(vec![1, 2, 3]);
        state.push_send_buffer(vec![4, 5]);
        state.push_send_buffer(vec![6, 7, 8, 9]);
        state.push_send_buffer(vec![10]);
        state.push_send_buffer(vec![11, 12]);

        // Technically this should be necessary.
        for _ in 0..4 {
            state.next_send_ack();
            state.next_send_chunk();
        }

        assert_eq!(state.send_buffer_space(), 0);

        // ACK past the end of the window.
        state.handle_ack(&Ack{
            window_start: 4,
            window_mask: vec![true, true, true, true]
        });
        assert_eq!(state.send_buffer_space(), 0);

        // This packet is ignored, because it indicates an invalid state.
        // The window is ahead of -3, meaning that we've seen a more recent
        // acknowledgement, so this stale ACK should not contain any bits that our
        // our newer ACK did not.
        state.handle_ack(&Ack{
            window_start: 0xfffffffd,
            window_mask: vec![true, true, true, true]
        });
        assert_eq!(state.send_buffer_space(), 0);

        // This is also invalid, since we are ACK'ing packets past the window.
        // However, the trailing ACKs are ignored in this case.
        state.handle_ack(&Ack{
            window_start: 0,
            window_mask: vec![false, true, true, true]
        });
        assert_eq!(state.send_buffer_space(), 2);

        // Packets within the maximum possible window, but not the current window.
        state.handle_ack(&Ack{
            window_start: 5,
            window_mask: vec![true, true, true, true]
        });
        assert_eq!(state.send_buffer_space(), 2);
        state.handle_ack(&Ack{
            window_start: 4,
            window_mask: vec![false, false, false, false]
        });
        assert_eq!(state.send_buffer_space(), 2);

        // Fill up the window.
        state.push_send_buffer(vec![3, 2, 1]);
        state.push_send_buffer(vec![5, 4]);
        for _ in 0..2 {
            state.next_send_ack();
            state.next_send_chunk();
        }

        // Now this ACK is in bounds.
        state.handle_ack(&Ack{
            window_start: 5,
            window_mask: vec![true, true, true, true]
        });
        assert_eq!(state.send_buffer_space(), 5);
    }

    fn trivial_endpoint() -> WwrState {
        WwrState::new(1, 1, 0)
    }

    fn basic_xfer(end1: &mut WwrState, end2: &mut WwrState) {
        let space1 = end1.send_buffer_space();
        let space2 = end2.send_buffer_space();
        assert!(space1 > 0);
        assert!(space2 > 0);

        // Both ends send one chunk.
        end1.push_send_buffer(vec![1, 2, 3, 4]);
        end2.push_send_buffer(vec![4, 3, 2, 1, 0]);

        // Simulate the first request.
        let ack1 = end1.next_send_ack();
        let chunk1 = end1.next_send_chunk().unwrap();
        assert_eq!(chunk1.data, vec![1, 2, 3, 4]);
        end2.handle_ack(&ack1);
        assert_eq!(end2.handle_chunk(chunk1.clone()), vec![chunk1]);

        let ack2 = end2.next_send_ack();
        let chunk2 = end2.next_send_chunk().unwrap();
        assert_eq!(chunk2.data, vec![4, 3, 2, 1, 0]);
        end1.handle_ack(&ack2);
        assert_eq!(end1.handle_chunk(chunk2.clone()), vec![chunk2]);

        // Simulate the second request.
        let ack3 = end1.next_send_ack();
        let chunk3 = end1.next_send_chunk();
        assert!(chunk3.is_none());
        end2.handle_ack(&ack3);

        let ack4 = end2.next_send_ack();
        let chunk4 = end2.next_send_chunk();
        assert!(chunk4.is_none());
        end1.handle_ack(&ack4);

        // Make sure the round-robin system isn't horribly broken.
        for _ in 0..3 {
            assert!(end1.next_send_chunk().is_none());
            assert!(end2.next_send_chunk().is_none());
        }

        assert_eq!(end1.send_buffer_space(), space1);
        assert_eq!(end2.send_buffer_space(), space2);
    }

    fn basic_eof(endpoint: &mut WwrState) {
        let empty_chunk = Chunk{
            seq: endpoint.next_send_ack().window_start,
            data: Vec::new()
        };
        assert_eq!(endpoint.handle_chunk(empty_chunk.clone()), vec![empty_chunk]);

        // We've gotten an EOF, but still haven't sent an EOF.
        assert!(!endpoint.is_done());

        endpoint.push_eof();
        let next_chunk = endpoint.next_send_chunk().unwrap();
        assert_eq!(next_chunk.data.len(), 0);

        // We've sent an EOF, but haven't gotten an ACK.
        assert!(!endpoint.is_done());

        let ack = Ack{
            window_start: (Wrapping(next_chunk.seq) + Wrapping(1)).0,
            window_mask: repeat(false).take((endpoint.out_win_size - 1) as usize).collect()
        };
        endpoint.handle_ack(&ack);
        assert!(endpoint.is_done());
    }

    fn windowed_eof(endpoint: &mut WwrState) {
        let empty_chunk = Chunk{
            seq: (Wrapping(endpoint.next_send_ack().window_start) + Wrapping(1)).0,
            data: Vec::new()
        };
        assert_eq!(endpoint.handle_chunk(empty_chunk.clone()).len(), 0);
        assert!(!endpoint.is_done());

        let data_chunk = Chunk{
            seq: endpoint.next_send_ack().window_start,
            data: vec![1, 2, 3]
        };
        assert_eq!(endpoint.handle_chunk(data_chunk.clone()), vec![data_chunk, empty_chunk]);

        // We've gotten an EOF, but still haven't sent an EOF.
        assert!(!endpoint.is_done());

        endpoint.push_send_buffer(vec![1, 2, 5, 4]);
        let out_chunk = endpoint.next_send_chunk().unwrap();
        assert_eq!(out_chunk.data, vec![1, 2, 5, 4]);

        endpoint.push_eof();
        // This is a subtle test for round-robin.
        let eof_chunk = endpoint.next_send_chunk().unwrap();
        assert_eq!(eof_chunk.data.len(), 0);

        // We've sent an EOF, but haven't gotten an ACK.
        assert!(!endpoint.is_done());

        let ack = Ack{
            window_start: out_chunk.seq,
            window_mask: vec![true].into_iter()
                .chain(repeat(false).take((endpoint.out_win_size - 2) as usize))
                .collect()
        };
        endpoint.handle_ack(&ack);
        assert!(!endpoint.is_done());

        let ack = Ack{
            window_start: (Wrapping(out_chunk.seq) + Wrapping(1)).0,
            window_mask: repeat(false).take((endpoint.out_win_size - 1) as usize).collect()
        };
        endpoint.handle_ack(&ack);
        assert!(endpoint.is_done());
    }

    fn reverse_window_in(endpoint: &mut WwrState, win_size: u32) {
        let start_seq = endpoint.next_send_ack().window_start;
        let mut final_chunks = Vec::new();
        let mut window_mask = endpoint.next_send_ack().window_mask;
        for i in (0u32..win_size).into_iter().rev() {
            let chunk = Chunk{
                seq: (Wrapping(start_seq) + Wrapping(i)).0,
                data: vec![((i + 17) & 0xff) as u8]
            };
            final_chunks.insert(0, chunk.clone());
            let chunks = endpoint.handle_chunk(chunk);
            if i != 0 {
                window_mask[(i - 1) as usize] = true;
                assert_eq!(chunks.len(), 0);
                assert_eq!(endpoint.next_send_ack(), Ack{
                    window_start: start_seq,
                    window_mask: window_mask.clone()
                });
            } else {
                assert_eq!(chunks, final_chunks);
                assert_eq!(endpoint.next_send_ack(), Ack{
                    window_start: (Wrapping(start_seq) + Wrapping(win_size)).0,
                    window_mask: repeat(false).take(window_mask.len()).collect()
                });
            }
        }
    }
}
