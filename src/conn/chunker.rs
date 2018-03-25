use std::io;
use std::io::{Read, Write};
use std::mem::replace;
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{SyncSender, Receiver, TrySendError, sync_channel};
use std::thread::spawn;

pub struct TcpChunker {
    stream: TcpStream,
    incoming: Receiver<Vec<u8>>,
    outgoing: SyncSender<Vec<u8>>,
    buffer_chunk: Option<Vec<u8>>
}

impl TcpChunker {
    pub fn new(stream: TcpStream, recv_mtu: usize, in_buf: usize, out_buf: usize)
        -> io::Result<TcpChunker> {
        let (in_sender, in_receiver) = sync_channel(in_buf);
        let (out_sender, out_receiver) = sync_channel(out_buf);
        let clone1 = stream.try_clone()?;
        let clone2 = stream.try_clone()?;
        // TODO: why is `move` necessary here, but not below?
        spawn(move || {
            TcpChunker::read_loop(in_sender, clone1, recv_mtu);
        });
        spawn(|| {
            TcpChunker::write_loop(out_receiver, clone2);
        });
        Ok(TcpChunker{
            stream: stream,
            incoming: in_receiver,
            outgoing: out_sender,
            buffer_chunk: None
        })
    }

    pub fn can_send(&mut self) -> bool {
        let old_chunk = replace(&mut self.buffer_chunk, None);
        if let Some(chunk) = old_chunk {
            self.send(chunk);
            self.buffer_chunk.is_none()
        } else {
            true
        }
    }

    pub fn send(&mut self, chunk: Vec<u8>) {
        assert!(self.buffer_chunk.is_none());
        self.buffer_chunk = match self.outgoing.try_send(chunk) {
            Ok(_) => None,
            Err(TrySendError::Full(x)) | Err(TrySendError::Disconnected(x)) => Some(x)
        }
    }

    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().ok()
    }

    fn write_loop(channel: Receiver<Vec<u8>>, mut stream: TcpStream) {
        for chunk in channel {
            if let Err(_) = stream.write_all(&chunk) {
                return;
            }
        }
    }

    fn read_loop(channel: SyncSender<Vec<u8>>, mut stream: TcpStream, chunk_size: usize) {
        let mut data = Vec::new();
        loop {
            for _ in 0..chunk_size {
                data.push(0u8);
            }
            if let Ok(size) = stream.read(&mut data) {
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
        self.stream.shutdown(Shutdown::Read).ok();
    }
}
