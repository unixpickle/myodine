use std::time::Duration;

use clap::{App, Arg};

use myodine::dns_proto::Domain;

pub struct Flags {
    pub listen_addr: String,
    pub password: String,
    pub host: Domain,
    pub conn_timeout: Duration,
    pub session_timeout: Duration,
    pub proof_window: u64
}

impl Flags {
    pub fn parse() -> Result<Flags, String> {
        let matches = App::new("myodine-server")
            .arg(Arg::with_name("addr")
                .short("a")
                .long("addr")
                .value_name("ADDR:PORT")
                .help("Set the address to listen on")
                .takes_value(true))
            .arg(Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("VALUE")
                .help("Set the server password")
                .takes_value(true))
            .arg(Arg::with_name("proof-win")
                .short("w")
                .long("proof-win")
                .value_name("INT")
                .help("Set the proof leniency window (in seconds)")
                .takes_value(true))
            .arg(Arg::with_name("conn-timeout")
                .short("c")
                .long("conn-timeout")
                .value_name("INT")
                .help("Set the outgoing connection timeout")
                .takes_value(true))
            .arg(Arg::with_name("sess-timeout")
                .short("s")
                .long("sess-timeout")
                .value_name("INT")
                .help("Set the session timeout")
                .takes_value(true))
            .arg(Arg::with_name("host")
                .help("Set the root domain name of the proxy")
                .required(true)
                .index(1))
            .get_matches();

        macro_rules! parse_arg {
            ( $name:expr, $default:expr ) => {
                matches.value_of($name).unwrap_or($default).parse()
                    .map_err(|e| format!("bad {} argument: {}", $name, e))
            }
        }

        Ok(Flags{
            listen_addr: String::from(matches.value_of("addr").unwrap_or("0.0.0.0:53")),
            password: String::from(matches.value_of("password").unwrap_or("")),
            host: parse_arg!("host", "")?,
            conn_timeout: Duration::new(parse_arg!("conn-timeout", "5")?, 0),
            session_timeout: Duration::new(parse_arg!("sess-timeout", "60")?, 0),
            proof_window: parse_arg!("proof-win", "120")?
        })
    }
}
