use myodine::dns_proto::domain::Domain;

#[derive(Clone)]
pub struct Flags {
    pub addr: String,
    pub host: Domain,
    pub concurrency: usize,
    pub password: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub listen_port: u16
}
