extern crate access;
extern crate clap;
extern crate daemonize;
extern crate futures;
extern crate sodiumoxide;
extern crate tokio_core;
extern crate tokio_process;

use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;
use std::collections::hash_map::Entry::*;
use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::rc::Rc;
use std::str;
use std::time::{Duration, Instant};

use access::keys::{KeyDataReader, ServerKeyData};
use access::state::{ServerState, StateManager};
use access::packet;
use access::err::AccessError;
use access::req::{SessReq, REQ_PORT};
use access::resp::{SessReqAction, SessResp};
use clap::{App, Arg};
use daemonize::Daemonize;
use futures::{future, Future, Stream};
use sodiumoxide::crypto::box_::{Nonce, NONCEBYTES};
use sodiumoxide::randombytes::randombytes;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_process::CommandExt;

const MAX_RENEWALS: u8 = 4;
const VERSION: &'static str = "2.0.1";
const DEFAULT_DURATION: &'static str = "900";
const DEFAULT_STATE_FILENAME: &'static str = "/var/db/accessd_state.yaml";
const DEFAULT_KEYDATA_FILENAME: &'static str = "/etc/accessd_keydata.yaml";

const DEFAULT_DAEMON_STDOUT_FILENAME: &'static str = "/var/log/accessd.out";
const DEFAULT_DAEMON_STDERR_FILENAME: &'static str = "/var/log/accessd.err";


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
    req_id: u64,
    duration: u64,
    req_addr: String,
    handle: Handle,
}

impl Session {
    fn new (cmd: &String, req_id: u64, duration: u64, req_addr: IpAddr, handle: &Handle) -> Self {
        Session {cmd: cmd.clone(), req_id: req_id, duration: duration,
                    req_addr: req_addr.to_string(), handle: handle.clone() }
    }
}

pub struct ServerCodec {
     cmd: String,
     duration: u64,
     handle: Handle,
     sessions: Rc<RefCell<HashMap<String,SessionInterval>>>,
     state: ServerState,
     key_data: ServerKeyData,
}

impl ServerCodec {

    fn new(state_filename: &str, key_data_filename: &str, access_cmd: &str, duration: u64,
           handle: &Handle) -> Result<Self, AccessError> {
        let state = ServerState::read(state_filename)?;
        let key_data = ServerKeyData::read(key_data_filename)?;

        Ok(ServerCodec {cmd: String::from(access_cmd),  duration: duration,
                     handle: handle.clone(), sessions: Rc::new(RefCell::new(HashMap::new())),
                     state: state, key_data: key_data})
    }

    fn get_sess(&mut self, addr: &SocketAddr, buf: &[u8]) -> Option<(String,Session)> {
        for (name, public_key) in &self.key_data.peer_public_keys {
            match packet::open(buf, &self.key_data.secret, public_key) {
                Ok(req_packet) => {
                    match SessReq::from_msg(&req_packet) {
                        Ok(recv_req) => {
                            let client_ip =
                                if recv_req.addr.is_unspecified() { addr.ip() } else { recv_req.addr };
                            return Some((name.clone(),Session::new(&self.cmd, recv_req.req_id, self.duration,
                                                                  client_ip, &self.handle)));
                        },
                        Err(e) => println!("invalid message from {:?}: {}", addr, e),
                    }
                },
                Err(_) => {}
            }
            println!("{}: {:?}", name, public_key);
        }
        None
    }
}

impl UdpCodec for ServerCodec {
    type In = (SocketAddr, Option<(String,Session)>, Rc<RefCell<HashMap<String, SessionInterval>>>);
    type Out = (SocketAddr, Option<(String,Session)>, Rc<RefCell<HashMap<String, SessionInterval>>>);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {

        Ok((*addr, self.get_sess(addr, buf), self.sessions.clone()))
    }

    fn encode(&mut self, (addr, sess_info, sessions): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        match sess_info {
            Some((name, req_sess)) => {
                let resp = match handle_incoming(&sessions, name.clone(), &req_sess, &mut self.state) {
                    grant @ SessResp {action: SessReqAction::Grant, ..} => {
                        grant_access(req_sess, sessions);
                        grant
                    },
                    renew @ SessResp {action: SessReqAction::Renew, ..} => {
                        renew_access(req_sess, sessions);
                        renew
                    },
                    deny =>  deny,
                };

                match self.key_data.peer_public_keys.get(&name) {
                    Some(peer_public) => {
                        let nonce: Nonce = Nonce::from_slice(&randombytes(NONCEBYTES)).unwrap();
                        into.extend(&nonce[..]);
                        match resp.to_msg() {
                            Ok(msg) => {
                                let encrypted_req_packet = packet::create(&msg, &nonce,
                                                                          &self.key_data.secret,
                                                                          peer_public);
                                into.extend(encrypted_req_packet);
                            },
                            Err(e) => println!("packet encoding failed: {}", e),
                        }
                    },
                    None => println!("no public key found for {}", name),
                }
            },
            None => println!("invalid request from {:?}", addr),
        }
        addr
    }
}

fn handle_incoming(sessions: &Rc<RefCell<HashMap<String,SessionInterval>>>, name: String,
                   req_sess: &Session, state: &mut ServerState) -> SessResp {

    let cur_req_id = match state.cur_req_ids.get(&name) {
        Some(req_id) => {
            println!("session for {}, req_id {}", name, req_id);
            *req_id
        },
        None => {
            println!("no request ID for {}", name);
            0
        },
    };

    if cur_req_id >= req_sess.req_id {
        return SessResp::new(SessReqAction::DenyDuplicateRequest, req_sess.req_id, 0, 0)
    } else {
        state.cur_req_ids.insert(name, req_sess.req_id);
        if let Err(e) = state.write() {
            println!("state file write failed: {}", e)
        }
    }

    let client_addr = req_sess.req_addr.clone();
    let mut sessions_mut = sessions.borrow_mut();
    let sess_interval = sessions_mut.entry(client_addr);
    match sess_interval {
        Occupied(mut entry) => {
            let sess_interval_mut = entry.get_mut();
            let elapsed = sess_interval_mut.timeout_start.elapsed().as_secs();
            let renew_ok_after = ((req_sess.duration as f64) * 0.75) as u64;
            if elapsed < renew_ok_after {
                SessResp::new(SessReqAction::DenyRenewTooSoon, req_sess.req_id, renew_ok_after - elapsed , 0)
            } else if sess_interval_mut.renewals >= MAX_RENEWALS {
                SessResp::new(SessReqAction::DenyMaxRenewalsReached, req_sess.req_id, 0, 0)
            } else if !sess_interval_mut.renew_ok {
                SessResp::new(SessReqAction::DenyRenewAlreadyInProgress, req_sess.req_id, 0, 0)
            } else {
                sess_interval_mut.timeout_start = Instant::now();
                sess_interval_mut.renew_ok = false;
                sess_interval_mut.renewals += 1;
                SessResp::new(SessReqAction::Renew, req_sess.req_id, req_sess.duration, MAX_RENEWALS - sess_interval_mut.renewals)
            }
        },
        Vacant(_) => SessResp::new(SessReqAction::Grant, req_sess.req_id, req_sess.duration, MAX_RENEWALS),
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

fn grant_access(new_sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>) {
    println!("new session for {}", new_sess.req_addr);

    new_sess.handle.clone().spawn(
        // 1: Execute the "grant" command.
        Command::new(&new_sess.cmd).arg("grant")
            .arg(&new_sess.req_addr)
            .output_async(&new_sess.handle).map(|output| {(output, new_sess, sessions)})
        // 2: Create a session for this client, and start a delay before the "revoke" command.
            .and_then(move |args| {
                let (output, new_sess, sessions) = args;
                create_session(&sessions, new_sess.req_addr.clone());
                print!("start command:\n{}", str::from_utf8(&output.stdout).unwrap());
                Timeout::new(Duration::from_secs(new_sess.duration), &new_sess.handle)
                    .unwrap().map(|_| { (new_sess, sessions) })
            })
        // 3: Continue processing after the timeout.
            .then( |args| {
                let (new_sess, sessions) = args.unwrap();
                manage_session(new_sess, sessions)
            })
    );
}

fn renew_access(existing_sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>) {
    println!("renew session for {}", existing_sess.req_addr);

    existing_sess.handle.clone().spawn(
        // 1: start a delay before executing "revoke" command
        Timeout::new(Duration::from_secs(existing_sess.duration), &existing_sess.handle)
            .unwrap().map(|_| { (existing_sess, sessions) })
        // 2: Continue processing after the timeout.
            .then( |args| {
                let (existing_sess, sessions) = args.unwrap();
                manage_session(existing_sess, sessions)
            })
    );
}

fn manage_session(active_sess: Session, sessions: Rc<RefCell<HashMap<String, SessionInterval>>>)
                  -> futures::future::FutureResult<(), ()> {

    match get_timeout_action(&sessions, &active_sess) {
        TimeoutCompleteAction::Revoke => {
            active_sess.handle.clone().spawn(
                Command::new(&active_sess.cmd).arg("revoke")
                    .arg(&active_sess.req_addr)
                    .output_async(&active_sess.handle).map(|output| {(output, active_sess, sessions)})
                    .then(move |args| {
                        let (output, active_sess, sessions) = args.unwrap();
                        {
                            let mut sessions_mut = sessions.borrow_mut();
                            {
                                let sess_interval_mut = sessions_mut.get_mut(&active_sess.req_addr).unwrap();
                                println!("removing {} after {} seconds ", active_sess.req_addr,
                                         sess_interval_mut.session_start.elapsed().as_secs());
                            }
                            sessions_mut.remove(&active_sess.req_addr);
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
            println!("{} unknown", active_sess.req_addr);
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
        .version(VERSION)
        .author("Chuck Musser <cmusser@sonic.net>")
        .about("Grant access to host")
        .arg(Arg::with_name("duration").empty_values(false)
             .short("d").long("duration").default_value(DEFAULT_DURATION)
             .help("Specify the client address"))
        .arg(Arg::with_name("state-file").empty_values(false)
             .short("s").long("state-file").default_value(DEFAULT_STATE_FILENAME)
             .help("Path to state file"))
        .arg(Arg::with_name("key-data-file").empty_values(false)
             .short("k").long("key-data-file").default_value(DEFAULT_KEYDATA_FILENAME)
             .help("Path to key data file"))
        .arg(Arg::with_name("foreground")
             .short("f").long("foreground")
             .help("Run in foreground"))
        .arg(Arg::with_name("CMD")
             .required(true)
             .help("Command to grant/revoke access"))
        .get_matches();

    if matches.is_present("foreground") {
        if let Err(e) = run(matches.value_of("state-file").unwrap(),
                            matches.value_of("key-data-file").unwrap(),
                            matches.value_of("CMD").unwrap(),
                            matches.value_of("duration").unwrap().parse::<u64>().unwrap()) {
            println!("failed: {}", e);
        }
    } else {
        match File::create(DEFAULT_DAEMON_STDOUT_FILENAME) {
            Ok(stdout) => {
                match File::create(DEFAULT_DAEMON_STDERR_FILENAME) {
                    Ok(stderr) => {
                        let daemonize = Daemonize::new()
                            .pid_file("/var/run/accessd.pid")
                            .stdout(stdout)
                            .stderr(stderr);
                        match daemonize.start() {
                            Ok(_) => {
                                println!("accessd starting");
                                if let Err(e) = run(matches.value_of("state-file").unwrap(),
                                                    matches.value_of("key-data-file").unwrap(),
                                                    matches.value_of("CMD").unwrap(),
                                                    matches.value_of("duration").unwrap().parse::<u64>().unwrap()) {
                                    println!("failed: {}", e);
                                }
                            },
                            Err(e) => eprintln!("failed: couldn't daemonize -- {}", e),
                        };
                    },
                    Err(e) => eprintln!("failed: couldn't open {} -- {}",
                                        DEFAULT_DAEMON_STDERR_FILENAME, e),
                }
            },
            Err(e) => eprintln!("failed: couldn't open {} -- {}",
                                DEFAULT_DAEMON_STDOUT_FILENAME, e),
        }
    }
}
