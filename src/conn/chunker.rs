use std::io;
use std::io::{Read, Write};
use std::mem::replace;
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{SyncSender, Receiver, TrySendError, sync_channel};
use std::thread::spawn;

/// A TCP connection that reads and writes data in chunks.
pub struct TcpChunker {
    stream: TcpStream,
    incoming: Receiver<Vec<u8>>,
    outgoing: Option<SyncSender<Vec<u8>>>,
    buffer_chunk: Option<Vec<u8>>
}

impl TcpChunker {
    /// Create a new TCP chunker.
    ///
    /// # Arguments
    ///
    /// * `stream` - A TCP stream to wrap.
    /// * `recv_mtu` - The maximum incoming chunk size.
    /// * `in_buf` - The number of incoming chunks to buffer.
    /// * `out_buf` - The number of outgoing chunks to buffer.
    pub fn new(
        stream: TcpStream,
        recv_mtu: usize,
        in_buf: usize,
        out_buf: usize
    ) -> io::Result<TcpChunker> {
        let (in_sender, in_receiver) = sync_channel(in_buf);
        let (out_sender, out_receiver) = sync_channel(out_buf);
        let clone1 = stream.try_clone()?;
        let clone2 = stream.try_clone()?;
        // TODO: why is `move` necessary here, but not below?
        spawn(move || {
            TcpChunker::read_loop(&in_sender, clone1, recv_mtu);
            in_sender.send(Vec::new()).ok();
        });
        spawn(|| {
            TcpChunker::write_loop(out_receiver, clone2);
        });
        Ok(TcpChunker{
            stream: stream,
            incoming: in_receiver,
            outgoing: Some(out_sender),
            buffer_chunk: None
        })
    }

    /// Check if there is room in the send buffer.
    ///
    /// If this returns false, it means that the source of data should apply
    /// backpressure.
    pub fn can_send(&mut self) -> bool {
        if self.outgoing.is_none() {
            return false;
        }
        let old_chunk = replace(&mut self.buffer_chunk, None);
        if let Some(chunk) = old_chunk {
            self.send(chunk);
            self.buffer_chunk.is_none()
        } else {
            true
        }
    }

    /// Send a chunk of data to the remote end.
    ///
    /// Before calling this, you should check can_send().
    pub fn send(&mut self, chunk: Vec<u8>) {
        assert!(self.outgoing.is_some());
        assert!(self.buffer_chunk.is_none());
        self.buffer_chunk = match self.outgoing.as_ref().unwrap().try_send(chunk) {
            Ok(_) => None,
            Err(TrySendError::Full(x)) | Err(TrySendError::Disconnected(x)) => Some(x)
        }
    }

    /// Send an EOF to the remote end.
    ///
    /// After calling this, you should not call send() again.
    /// This should be fine, since can_send() will return false.
    pub fn send_finished(&mut self) {
        assert!(self.outgoing.is_some());
        if let Some(data) = replace(&mut self.buffer_chunk, None) {
            let ch = replace(&mut self.outgoing, None);
            spawn(|| {
                ch.unwrap().send(data).ok();
            });
        } else {
            self.outgoing = None;
        }
    }

    /// Receive the next chunk if one is available.
    ///
    /// If no new chunks are available, None is returned.
    /// An empty chunk represents EOF.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.try_recv().ok()
    }

    fn write_loop(channel: Receiver<Vec<u8>>, mut stream: TcpStream) {
        for chunk in channel {
            if let Err(_) = stream.write_all(&chunk) {
                return;
            }
        }
        stream.shutdown(Shutdown::Write).ok();
    }

    fn read_loop(channel: &SyncSender<Vec<u8>>, mut stream: TcpStream, chunk_size: usize) {
        let mut data = Vec::new();
        for _ in 0..chunk_size {
            data.push(0u8);
        }
        loop {
            if let Ok(size) = stream.read(&mut data) {
                if size == 0 {
                    // For some reason, this seems to happen on EOF.
                    return;
                }
                if channel.send(data[0..size].to_vec()).is_err() {
                    return;
                }
            } else {
                return;
            }
        }
    }
}

impl Drop for TcpChunker {
    fn drop(&mut self) {
        // Force the read loop to die.
        self.stream.shutdown(Shutdown::Read).ok();
    }
}
