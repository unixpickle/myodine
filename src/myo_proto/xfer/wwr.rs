use std::num::Wrapping;

use myo_proto::xfer::types::{Ack, Chunk};

pub struct WwrState {
    in_win_size: u16,
    in_win_start: u32,
    in_received: Vec<Chunk>,

    out_win_size: u16,
    out_next_seq: u32,
    out_win_start: u32,
    out_pending: Vec<Chunk>,
    out_round_robin: usize
}

impl WwrState {
    pub fn new(in_win_size: u16, out_win_size: u16, seq_start: u32) -> WwrState {
        WwrState{
            in_win_size: in_win_size,
            in_win_start: seq_start,
            in_received: Vec::new(),

            out_win_size: out_win_size,
            out_next_seq: seq_start,
            out_win_start: seq_start,
            out_pending: Vec::new(),
            out_round_robin: 0
        }
    }

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

    pub fn send_buffer_space(&self) -> usize {
        let win_used = (Wrapping(self.out_next_seq) - Wrapping(self.out_win_start)).0;
        assert!((win_used as usize) < (self.out_win_size as usize));
        (self.out_win_size as usize) - (win_used as usize)
    }

    pub fn push_send_buffer(&mut self, data: Vec<u8>) {
        let chunk = Chunk{seq: self.out_next_seq, data: data};
        self.out_next_seq = (Wrapping(self.out_next_seq) + Wrapping(1)).0;
        self.out_pending.push(chunk);
    }

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

    pub fn handle_chunk(&mut self, chunk: Chunk) -> Vec<Chunk> {
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
                    result.push(self.in_received.swap_remove(i));
                    self.in_win_start += 1;
                    got_chunk = true;
                    break;
                }
            }
        }
        result
    }

    fn remove_out_seq(&mut self, seq: u32) {
        for i in 0..self.out_pending.len() {
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
