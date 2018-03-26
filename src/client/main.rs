extern crate clap;
extern crate myodine;

mod flags;
mod discovery;
mod establish;
mod session;

use std::net::{TcpListener, TcpStream};
use std::process::exit;

use clap::{Arg, App};

use flags::Flags;
use discovery::discover_features;
use establish::establish;
use session::Session;

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

    // TODO: add a bunch of flags here.

    // TODO: macro for error handling.

    let flags = Flags{
        addr: String::from(matches.value_of("addr").unwrap_or("localhost:53")),
        host: matches.value_of("host").unwrap().parse().unwrap(),
        concurrency: matches.value_of("concurrency").unwrap().parse().unwrap(),
        password: String::from("password"),
        remote_addr: String::from("localhost"),
        remote_port: 1337,
        listen_port: 1234
    };

    println!("Waiting for incoming connection...");
    // TODO: handle listen error better.
    let listener = TcpListener::bind(format!("localhost:{}", flags.listen_port)).unwrap();
    let (conn, _) = listener.accept().unwrap();

    println!("Discovering features @{} for {}...", flags.host, flags.addr);
    let features = discover_features(&flags.addr, &flags.host);
    if let &Err(ref err) = &features {
        eprintln!("Failed to discover features: {}", err);
        exit(1);
    }
    let features = features.unwrap();

    // TODO: handle errors better.
    println!("Establishing session...");
    let establishment = establish(&flags, features).unwrap();
    println!("Running session...");
    Session::new(&flags, conn, establishment).unwrap().run();
}
