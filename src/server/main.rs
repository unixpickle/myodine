extern crate clap;
extern crate myodine;

mod flags;
mod session;
mod server;

use std::net::UdpSocket;
use std::process::exit;
use std::time::Duration;

use clap::{Arg, App};
use myodine::dns_coding::{dns_decode, dns_encode};
use myodine::dns_proto::message::Message;

use flags::Flags;
use server::Server;

fn main() {
    let matches = App::new("myodine-server")
        .arg(Arg::with_name("addr")
            .short("a")
            .long("addr")
            .value_name("ADDR:PORT")
            .help("Set the address to listen on")
            .takes_value(true))
        .get_matches();
    let addr = matches.value_of("addr").unwrap_or("localhost:53");

    // TODO: add timeout flags.
    // TODO: add password flag.
    // TODO: add host flag.
    // TODO: add proof window flag.

    let flags = Flags{
        listen_addr: String::from(addr),
        password: String::from("password"),
        host: "foo.com".parse().unwrap(),
        conn_timeout: Duration::new(5, 0),
        session_timeout: Duration::new(30, 0),
        proof_window: 100
    };

    let socket = UdpSocket::bind(addr);
    if socket.is_err() {
        eprintln!("failed to listen: {}", socket.err().unwrap());
        exit(1);
    }
    let socket = socket.unwrap();
    socket.set_read_timeout(Some(flags.session_timeout / 2)).unwrap();
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
