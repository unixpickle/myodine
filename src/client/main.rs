extern crate chrono;
extern crate clap;
extern crate myodine;

mod flags;
mod logger;
mod discovery;
mod establish;
mod session;

use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::thread::spawn;

use flags::Flags;
use logger::RawLogger;
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

    let listener = TcpListener::bind(&format!("localhost:{}", flags.listen_port)).
        map_err(|e| format!("listen error: {}", e))?;

    let logger = RawLogger::new();
    logger.log("listening for connections...".to_owned());
    loop {
        let (conn, addr) = listener.accept().map_err(|e| format!("accept error: {}", e))?;
        logger.log(format!("new connection from {}", addr));
        let local_flags = flags.clone();
        let local_logger = logger.clone();
        spawn(move || {
            if let Err(msg) = handle_connection(local_flags, conn, &local_logger) {
                local_logger.log(format!("error for {}: {}", addr, msg));
            } else {
                local_logger.log(format!("session ended for {}", addr));
            }
        });
    }
}

fn handle_connection(flags: Flags, conn: TcpStream, logger: &RawLogger) -> Result<(), String> {
    logger.log(format!("discovering features @{} for {}...", flags.host, flags.addr));
    let features = discover_features(&flags)
        .map_err(|e| format!("failed to discover features: {}", e))?;
    logger.log("establishing session...".to_owned());
    let establishment = establish(&flags, features)?;
    logger.log("running session...".to_owned());
    run_session(flags, conn, establishment, logger)
}
