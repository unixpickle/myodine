extern crate clap;
extern crate myodine;

mod flags;
mod discovery;
mod establish;
mod session;

use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::mpsc::{Sender, channel};
use std::thread::spawn;

use flags::Flags;
use discovery::discover_features;
use establish::establish;
use session::run_session;

fn main() {
    if let Err(msg) = main_or_err() {
        eprintln!("{}", msg);
        exit(1);
    }
}

fn main_or_err() -> Result<(), String> {
    let flags = Flags::parse()?;

    let (log_sender, log_receiver) = channel();
    spawn(|| {
        for msg in log_receiver {
            eprintln!("{}", msg);
        }
    });

    let listener = TcpListener::bind(&format!("localhost:{}", flags.listen_port)).
        map_err(|e| format!("listen error: {}", e))?;

    log_sender.send("listening for connections...".to_owned()).unwrap();
    loop {
        let (conn, addr) = listener.accept().map_err(|e| format!("accept error: {}", e))?;
        log_sender.send(format!("new connection from {}", addr)).unwrap();
        let local_flags = flags.clone();
        let local_logger = log_sender.clone();
        spawn(move || {
            if let Err(msg) = handle_connection(local_flags, conn, &local_logger) {
                local_logger.send(format!("error for {}: {}", addr, msg)).unwrap();
            } else {
                local_logger.send(format!("session ended for {}", addr)).unwrap();
            }
        });
    }
}

fn handle_connection(flags: Flags, conn: TcpStream, log: &Sender<String>) -> Result<(), String> {
    log.send(format!("discovering features @{} for {}...", flags.host, flags.addr)).unwrap();
    let features = discover_features(&flags)
        .map_err(|e| format!("failed to discover features: {}", e))?;
    log.send("establishing session...".to_owned()).unwrap();
    let establishment = establish(&flags, features)?;
    log.send("running session...".to_owned()).unwrap();
    run_session(flags, conn, establishment, log)
}
