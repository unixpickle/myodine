extern crate clap;
extern crate myodine;

mod flags;
mod session;
mod server;

use std::net::UdpSocket;
use std::process::exit;

use myodine::dns_coding::{dns_decode, dns_encode};
use myodine::dns_proto::Message;

use flags::Flags;
use server::Server;

fn main() {
    if let Err(msg) = main_or_err() {
        eprintln!("{}", msg);
        exit(1);
    }
}

fn main_or_err() -> Result<(), String> {
    let flags = Flags::parse()?;

    let socket = UdpSocket::bind(&flags.listen_addr)
        .map_err(|e| format!("listen failed: {}", e))?;
    socket.set_read_timeout(Some(flags.session_timeout / 2))
        .map_err(|e| format!("socket error: {}", e))?;

    let mut server = Server::new(flags);
    loop {
        let mut buf = [0; 2048];
        let result = socket.recv_from(&mut buf);
        server.garbage_collect();
        if result.is_err() {
            continue;
        }
        let (size, sender_addr) = result.unwrap();
        if let Ok(message) = dns_decode::<Message>(buf[0..size].to_vec()) {
            match server.handle_message(message) {
                Ok(response) => match dns_encode(&response) {
                    Ok(out_buf) => {
                        if socket.send_to(&out_buf, &sender_addr).is_err() {
                            eprintln!("send to {} failed", sender_addr);
                        }
                    },
                    Err(err) => eprintln!("error encoding response to {}: {}", sender_addr, err)
                }
                Err(err) => eprintln!("error processing query from {}: {}", sender_addr, err)
            }
        }
    }
}
