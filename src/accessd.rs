#[macro_use]
#[allow(unused)]
extern crate clap;
extern crate access;
extern crate tokio_core;
extern crate tokio_process;
extern crate futures;
extern crate sodiumoxide;

use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;
use std::collections::hash_map::Entry::*;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::rc::Rc;
use std::str;
use std::time::{Duration, Instant};

use access::keys::KeyData;
use access::state::State;
use access::payload::Payload;
use access::err::AccessError;
use access::req::{AccessReq, REQ_PORT};
use access::resp::{SessReqAction, SessResp};
use clap::App;
use futures::{future, Future, Stream};
use sodiumoxide::crypto::box_;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_process::CommandExt;

const MAX_RENEWALS: u8 = 4;

enum TimeoutCompleteAction {
    Revoke,
    Renew,
    Unknown,
}

pub struct SessionInterval {
    session_start: Instant,
    timeout_start: Instant,
    renew_ok: bool,
    renewals: u8,
}

impl SessionInterval {
    fn new() -> SessionInterval {
        SessionInterval {session_start: Instant::now(), timeout_start: Instant::now(),
                     renew_ok: true, renewals: 0 }
    }
}

pub struct Session {
    cmd: String,
    duration: u64,
    req_addr: String,
    handle: Handle,
}

impl Session {
    fn new (cmd: &String, duration: u64, req_addr: IpAddr, handle: &Handle) -> Self {
        Session {cmd: cmd.clone(), duration: duration,
                    req_addr: req_addr.to_string(), handle: handle.clone() }
    }
}

pub struct ServerCodec {
     cmd: String,
     duration: u64,
     handle: Handle,
     sessions: Rc<RefCell<HashMap<String,SessionInterval>>>,
     state: State,
     key_data: KeyData,
}

impl ServerCodec {

    fn new(state_filename: &str, key_data_filename: &str, access_cmd: &str, duration: u64,
           handle: &Handle) -> Result<Self, AccessError> {
        let state = State::read(state_filename)?;
        let key_data = KeyData::read(key_data_filename)?;

        Ok(ServerCodec {cmd: String::from(access_cmd),  duration: duration,
                     handle: handle.clone(), sessions: Rc::new(RefCell::new(HashMap::new())),
                     state: state, key_data: key_data})
    }
}

impl UdpCodec for ServerCodec {
    type In = (SocketAddr, Result<Session, AccessError>, Rc<RefCell<HashMap<String, SessionInterval>>>);
    type Out = (SocketAddr, Result<Session, AccessError>, Rc<RefCell<HashMap<String, SessionInterval>>>);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {

        let sess_result = match Payload::from_packet(buf).and_then(|payload| {
            payload.decrypt(&mut self.state, &self.key_data)
        }) {
            Ok(req_packet) => {
                match AccessReq::from_msg(&req_packet) {
                    Ok(recv_req) => {
                        let client_ip =
                            if recv_req.addr.is_unspecified() { addr.ip() } else { recv_req.addr };
                        Ok(Session::new(&self.cmd, self.duration, client_ip, &self.handle))
                    },
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e)
        };
        Ok((*addr, sess_result, self.sessions.clone()))
    }

    fn encode(&mut self, (addr, sess, sessions): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        match sess {
            Ok(sess) => {
                let resp = match handle_incoming(&sessions, &sess) {
                    grant @ SessResp {action: SessReqAction::Grant, ..} => {
                        grant_access(sess, sessions);
                        grant
                    },
                    renew @ SessResp {action: SessReqAction::Renew, ..} => {
                        renew_access(sess, sessions);
                        renew
                    },
                    deny =>  deny,
                };

                self.state.local_nonce.increment_le_inplace();
                into.extend(&self.state.local_nonce[..]);
                let encrypted_req_packet = box_::seal(&resp.to_msg(),
                                                      &self.state.local_nonce,
                                                      &self.key_data.peer_public,
                                                      &self.key_data.secret);
                if let Err(e) = self.state.write() {
                    println!("state file write failed: {}", e)
                }
                into.extend(encrypted_req_packet);
            },
            Err(e) => println!("invalid sess from {:?}: {}", addr, e),
        }
        addr
    }
}

fn handle_incoming(sessions: &Rc<RefCell<HashMap<String,SessionInterval>>>, sess: &Session) -> SessResp {
    let client_addr = sess.req_addr.clone();
    let mut sessions_mut = sessions.borrow_mut();
    let sess_interval = sessions_mut.entry(client_addr);
    match sess_interval {
        Occupied(mut entry) => {
            let sess_interval_mut = entry.get_mut();
            let elapsed = sess_interval_mut.timeout_start.elapsed().as_secs();
            let renew_ok_after = ((sess.duration as f64) * 0.75) as u64;
            if elapsed < renew_ok_after {
                SessResp::new(SessReqAction::DenyRenewTooSoon, renew_ok_after - elapsed , 0)
            } else if sess_interval_mut.renewals >= MAX_RENEWALS {
                SessResp::new(SessReqAction::DenyMaxRenewalsReached, 0, 0)
            } else if !sess_interval_mut.renew_ok {
                SessResp::new(SessReqAction::DenyRenewAlreadyInProgress, 0, 0)
            } else {
                sess_interval_mut.timeout_start = Instant::now();
                sess_interval_mut.renew_ok = false;
                sess_interval_mut.renewals += 1;
                SessResp::new(SessReqAction::Renew, sess.duration, MAX_RENEWALS - sess_interval_mut.renewals)
            }
        },
        Vacant(_) => SessResp::new(SessReqAction::Grant, sess.duration, MAX_RENEWALS),
    }
}

fn create_session(sessions: &Rc<RefCell<HashMap<String,SessionInterval>>>, client_addr: String) {
    let mut sessions_mut = sessions.borrow_mut();
    sessions_mut.entry(client_addr).or_insert(SessionInterval::new());
}

fn  get_timeout_action(sessions: &Rc<RefCell<HashMap<String,SessionInterval>>>, sess: &Session)
                       -> TimeoutCompleteAction {
    let client_addr = sess.req_addr.clone();
    let mut sessions_mut = sessions.borrow_mut();
    let sess_interval = sessions_mut.entry(client_addr);
    match sess_interval {
        Occupied(mut entry) => {
            let sess_interval_mut = entry.get_mut();
            if sess_interval_mut.timeout_start.elapsed().as_secs() >= sess.duration {
                TimeoutCompleteAction::Revoke
            } else {
                sess_interval_mut.renew_ok = true;
                TimeoutCompleteAction::Renew
            }
        },
        Vacant(_) => {
            TimeoutCompleteAction::Unknown
        }
    }
}

fn grant_access(sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>) {
    println!("new session for {}", sess.req_addr);

    sess.handle.clone().spawn(
        // 1: Execute the "grant" command.
        Command::new(&sess.cmd).arg("grant")
            .arg(&sess.req_addr)
            .output_async(&sess.handle).map(|output| {(output, sess, sessions)})
        // 2: Create a session for this client, and start a delay before the "revoke" command.
            .and_then(move |args| {
                let (output, sess, sessions) = args;
                create_session(&sessions, sess.req_addr.clone());
                print!("start command:\n{}", str::from_utf8(&output.stdout).unwrap());
                Timeout::new(Duration::from_secs(sess.duration), &sess.handle)
                    .unwrap().map(|_| { (sess, sessions) })
            })
        // 3: Continue processing after the timeout.
            .then( |args| {
                let (sess, sessions) = args.unwrap();
                manage_session(sess, sessions)
            })
    );
}

fn renew_access(sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>) {
    println!("renew session for {}", sess.req_addr);

    sess.handle.clone().spawn(
        // 1: start a delay before executing "revoke" command
        Timeout::new(Duration::from_secs(sess.duration), &sess.handle)
            .unwrap().map(|_| { (sess, sessions) })
        // 2: Continue processing after the timeout.
            .then( |args| {
                let (sess, sessions) = args.unwrap();
                manage_session(sess, sessions)
            })
    );
}

fn manage_session(sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>)
                  -> futures::future::FutureResult<(), ()> {

    match get_timeout_action(&sessions, &sess) {
        TimeoutCompleteAction::Revoke => {
            sess.handle.clone().spawn(
                Command::new(&sess.cmd).arg("revoke")
                    .arg(&sess.req_addr)
                    .output_async(&sess.handle).map(|output| {(output, sess, sessions)})
                    .then(move |args| {
                        let (output, sess, sessions) = args.unwrap();
                        {
                            let mut sessions_mut = sessions.borrow_mut();
                            {
                                let sess_interval_mut = sessions_mut.get_mut(&sess.req_addr).unwrap();
                                println!("removing {} after {} seconds ", sess.req_addr,
                                         sess_interval_mut.session_start.elapsed().as_secs());
                            }
                            sessions_mut.remove(&sess.req_addr);
                        }

                        print!("stop command:\n{}", str::from_utf8(&output.stdout).unwrap());
                        future::ok(())
                    }));
            future::ok(())
        },
        TimeoutCompleteAction::Renew => {
            future::ok(())
        },
        TimeoutCompleteAction::Unknown => {
            println!("{} unknown", sess.req_addr);
            future::ok(())
        }
    }
}

fn run(state_filename: &str, key_data_filename: &str, access_cmd: &str, duration: u64)
       -> Result<(), AccessError> {

    let mut core = Core::new().map_err(|e| { AccessError::IoError(e) })?;
    let handle = core.handle();

    let codec = ServerCodec::new(state_filename, key_data_filename, access_cmd,
                                 duration, &handle)?;

    let addr: SocketAddr = format!("0.0.0.0:{}", REQ_PORT).parse()
        .map_err(|e| { AccessError::InvalidAddr(e) })?;
    let sock = UdpSocket::bind(&addr, &handle)
        .map_err(|e| { AccessError::IoError(e) })?;

    let (framed_tx, framed_rx) = sock.framed(codec).split();
    let incoming = framed_rx.forward(framed_tx);

    Ok(drop(core.run(incoming)))
}

fn main() {

    let matches = App::new("accessd")
        .version("1.0")
        .author("Chuck Musser <cmusser@sonic.net>")
        .about("Grant access to host")
        .args_from_usage(
            "-d, --duration=[seconds] 'duration of access period (default: 900)'
             -s, --state-file=[filename] 'state file'
             -k, --key-data-file=[filename] 'key file'
             <CMD>              'command to grant/revoke access'").get_matches();

    let access_cmd = matches.value_of("CMD").unwrap();
    let duration = matches.value_of("duration").unwrap_or("900").parse::<u64>().unwrap();
    let state_filename = matches.value_of("state-file").unwrap_or("accessd_state.yaml");
    let key_data_filename = matches.value_of("key-data-file").unwrap_or("accessd_keydata.yaml");

    if let Err(e) = run(state_filename, key_data_filename, access_cmd, duration) {
        println!("failed: {}", e);
    }
}
