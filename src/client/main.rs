extern crate clap;
extern crate myodine;

use std::process::exit;
use std::sync::mpsc::channel;

use clap::{Arg, App};

mod discovery;
mod events;
mod requester;
use discovery::{Features, discover_features};
use requester::Requester;

fn main() {
    let matches = App::new("myodine-client")
        .arg(Arg::with_name("addr")
            .short("a")
            .long("addr")
            .value_name("ADDR:PORT")
            .help("Set the address of the DNS server")
            .takes_value(true))
        .arg(Arg::with_name("concurrency")
            .short("c")
            .long("concurrency")
            .value_name("NUM")
            .help("Set the maximum number of concurrent requests")
            .takes_value(true))
        .arg(Arg::with_name("host")
            .help("Set the root domain name of the proxy")
            .required(true)
            .index(1))
        .get_matches();

    let addr = matches.value_of("addr").unwrap_or("localhost:53");
    let host = matches.value_of("host").unwrap();
    let concurrency = matches.value_of("concurrency").unwrap().parse().unwrap();

    let parsed_host = host.parse();
    if let &Err(ref err) = &parsed_host {
        eprintln!("Invalid host: {}", err);
        exit(1);
    }

    println!("Discovering features @{} for {}...", host, addr);
    match discover_features(&addr, parsed_host.as_ref().unwrap()) {
        Ok(features) => {
            println!("Features: receive_mtu={} send_mtu={}", features.receive_mtu, features.send_mtu);
            println!("Creating requester...");
            let (event_sender, event_receiver) = channel();
            let requester = Requester::open(&addr, concurrency, event_sender);
        }
        Err(err) => {
            eprintln!("Failed to discover features: {}", err);
            exit(1);
        }
    }

}
