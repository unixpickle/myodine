extern crate clap;
extern crate myodine;

use std::net::UdpSocket;
use std::process::exit;

use clap::{Arg, App};
use myodine::dns_coding::{dns_decode, dns_encode};
use myodine::dns_proto::header::ResponseCode;
use myodine::dns_proto::message::Message;
use myodine::myo_proto::discovery;

mod session;
use session::Session;

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

    let socket_res = UdpSocket::bind(addr);
    if socket_res.is_err() {
        eprintln!("failed to listen: {}", socket_res.err().unwrap());
        exit(1);
    }
    let socket = socket_res.unwrap();
    let mut server = Server::new();
    loop {
        let mut buf = [0; 2048];
        let (size, sender_addr) = socket.recv_from(&mut buf).unwrap();
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

struct Server {
    // TODO: state here for connections, etc.
}

impl Server {
    fn new() -> Server {
        Server{}
    }

    fn handle_message(&mut self, message: Message) -> Result<Message, String> {
        if discovery::is_domain_hash_query(&message) {
            discovery::domain_hash_response(&message)
        } else if discovery::is_download_gen_query(&message) {
            discovery::download_gen_response(&message)
        } else {
            let mut response = message.clone();
            response.header.response_code = ResponseCode::NoError;
            Ok(response)
        }
    }
}
