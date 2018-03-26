use std::time::Duration;

use myodine::dns_proto::domain::Domain;

pub struct Flags {
    pub listen_addr: String,
    pub password: String,
    pub host: Domain,
    pub conn_timeout: Duration,
    pub session_timeout: Duration,
    pub proof_window: u64
}
