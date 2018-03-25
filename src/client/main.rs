extern crate clap;
extern crate myodine;

use std::process::exit;

use clap::{Arg, App};

mod discovery;
use discovery::{Features, discover_features};

fn main() {
    let matches = App::new("myodine-client")
        .arg(Arg::with_name("addr")
            .short("a")
            .long("addr")
            .value_name("ADDR:PORT")
            .help("Set the address of the DNS server")
            .takes_value(true))
        .arg(Arg::with_name("host")
            .help("Set the root domain name of the proxy")
            .required(true)
            .index(1))
        .get_matches();

    let addr = matches.value_of("addr").unwrap_or("localhost:53");
    let host = matches.value_of("host").unwrap();

    let parsed_host = host.parse();
    if let &Err(ref err) = &parsed_host {
        eprintln!("Invalid host: {}", err);
        exit(1);
    }

    println!("Discovering features @{} for {}...", host, addr);
    match discover_features(&addr, parsed_host.as_ref().unwrap()) {
        Ok(features) => {
            println!("Features: receive_mtu={} send_mtu={}", features.receive_mtu, features.send_mtu);
        }
        Err(err) => {
            eprintln!("Failed to discover features: {}", err);
            exit(1);
        }
    }

}
