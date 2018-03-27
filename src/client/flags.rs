use clap::{App, Arg};

use myodine::dns_proto::Domain;

#[derive(Clone)]
pub struct Flags {
    pub addr: String,
    pub host: Domain,
    pub concurrency: usize,
    pub password: String,
    pub remote_host: Domain,
    pub remote_port: u16,
    pub listen_port: u16
}

impl Flags {
    pub fn parse() -> Result<Flags, String> {
        let matches = App::new("myodine-client")
            .arg(Arg::with_name("concurrency")
                .short("c")
                .long("concurrency")
                .value_name("NUM")
                .help("Set the maximum number of concurrent requests")
                .takes_value(true))
            .arg(Arg::with_name("remote-host")
                .short("r")
                .long("remote-host")
                .value_name("ADDR")
                .help("Set the remote address to proxy to")
                .takes_value(true))
            .arg(Arg::with_name("remote-port")
                .short("n")
                .long("remote-port")
                .value_name("PORT")
                .help("Set the remote port to proxy to")
                .takes_value(true))
            .arg(Arg::with_name("listen-port")
                .short("l")
                .long("listen-port")
                .value_name("PORT")
                .help("Set the local port to listen on")
                .takes_value(true))
            .arg(Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("VALUE")
                .help("Set the server password")
                .takes_value(true))
            .arg(Arg::with_name("addr")
                .help("Set the address of the proxy")
                .required(true)
                .index(1))
            .arg(Arg::with_name("host")
                .help("Set the root domain name of the proxy")
                .required(true)
                .index(2))
            .get_matches();

        macro_rules! parse_arg {
            ( $name:expr, $default:expr ) => {
                matches.value_of($name).unwrap_or($default).parse()
                    .map_err(|e| format!("bad {} argument: {}", $name, e))
            }
        }

        Ok(Flags{
            addr: String::from(matches.value_of("addr").unwrap_or("localhost:53")),
            host: parse_arg!("host", "")?,
            concurrency: parse_arg!("concurrency", "2")?,
            password: String::from(matches.value_of("password").unwrap_or("")),
            remote_host: parse_arg!("remote-host", "localhost")?,
            remote_port: parse_arg!("remote-port", "22")?,
            listen_port: parse_arg!("listen-port", "2222")?
        })
    }
}
