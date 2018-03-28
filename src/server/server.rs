use std::iter::Iterator;
use std::time::{SystemTime, UNIX_EPOCH};

use myodine::myo_proto::discovery;
use myodine::myo_proto::establish;
use myodine::myo_proto::xfer;
use myodine::dns_proto::{Message, ResponseCode};

use flags::Flags;
use session::Session;

pub struct Server {
    flags: Flags,
    sessions: Vec<Session>
}

impl Server {
    pub fn new(flags: Flags) -> Server {
        Server{flags: flags, sessions: Vec::new()}
    }

    pub fn garbage_collect(&mut self) {
        for i in (0..self.sessions.len()).into_iter().rev() {
            if self.sessions[i].is_done(self.flags.session_timeout) {
                self.sessions.remove(i);
            }
        }
    }

    pub fn handle_message(&mut self, message: Message) -> Result<Message, String> {
        if discovery::is_domain_hash_query(&message) {
            return discovery::domain_hash_response(&message);
        } else if discovery::is_download_gen_query(&message) {
            return discovery::download_gen_response(&message);
        } else if establish::is_establish_query(&message) {
            return self.handle_establish(message);
        } else if let Some(id) = xfer::xfer_query_session_id(&message) {
            let mut some_sess = (&mut self.sessions).into_iter().find(|x| x.session_id() == id);
            if let Some(ref mut session) = some_sess {
                return session.handle_message(message, &self.flags.host);
            }
        }
        let mut response = message.clone();
        response.header.is_response = true;
        response.header.response_code = ResponseCode::NoError;
        Ok(response)
    }

    pub fn handle_establish(&mut self, message: Message) -> Result<Message, String> {
        let query = establish::EstablishQuery::from_query(&message, &self.flags.host)?;
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let response = if query.check_proof(&self.flags.password, epoch, self.flags.proof_window) {
            if let Some(id) = self.unused_session_id() {
                // TODO: randomize seq_start.
                let seq_start = 0;
                let sess_res = Session::new(id, seq_start, message.questions[0].record_type,
                    &query, self.flags.conn_timeout);
                match sess_res {
                    Ok(sess) => {
                        self.sessions.push(sess);
                        establish::EstablishResponse::Success{id: id, seq: seq_start}
                    },
                    Err(msg) => establish::EstablishResponse::Failure(msg)
                }

            } else {
                establish::EstablishResponse::Failure(String::from("no free session IDs"))
            }
        } else {
            establish::EstablishResponse::Failure(String::from("invalid proof"))
        };
        establish::establish_response(&message, &self.flags.host, response)
    }

    fn unused_session_id(&self) -> Option<u16> {
        for i in 0u16..65535 {
            if !(&self.sessions).into_iter().any(|x| x.session_id() == i) {
                return Some(i);
            }
        }
        None
    }
}
