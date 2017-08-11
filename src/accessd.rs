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

use access::crypto::{State, KeyData};
use access::err::AccessError;
use access::req::{AccessReq, REQ_PORT};
use access::resp::SessReqAction;
use clap::App;
use futures::{future, Future, Stream};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::*;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_process::CommandExt;

enum TimeoutCompleteAction {
    Revoke,
    Extend,
    Unknown,
}

pub struct Payload<'packet> {
    nonce: Nonce,
    encrypted_req: &'packet[u8],
}

impl<'packet> Payload<'packet> {
    fn from_packet(packet: &'packet[u8]) -> Result<Self, AccessError> {
        let nonce = Nonce::from_slice(&packet[..NONCEBYTES]);
        match nonce {
            Some(nonce) => Ok(Payload { nonce: nonce, encrypted_req: &packet[NONCEBYTES..] }),
            None => Err(AccessError::InvalidNonce),
        }
    }

    fn decrypt(&self, state: &mut State, key_data: &KeyData) -> Result<Vec<u8>, AccessError> {
        if self.nonce.lt(&state.nonce) {
            Err(AccessError::ReusedNonce)
        } else {
            state.nonce = self.nonce;
            state.write()?;
            box_::open(&self.encrypted_req, &self.nonce, &key_data.peer_public,
                       &key_data.secret).map_err(|_| { AccessError::InvalidCiphertext })
        }
    }
}

pub struct ClientLease {
    lease_start: Instant,
    timeout_start: Instant,
    renew_ok: bool,
    leases: u8,
}

impl ClientLease {
    fn new() -> ClientLease {
        ClientLease {lease_start: Instant::now(), timeout_start: Instant::now(),
                     renew_ok: true, leases: 1 }
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

pub struct AccessCodec {
     cmd: String,
     duration: u64,
     handle: Handle,
     sessions: Rc<RefCell<HashMap<String,ClientLease>>>,
     state: State,
     key_data: KeyData,
}

impl AccessCodec {

    fn new(state_filename: &str, key_data_filename: &str, access_cmd: &str, duration: u64,
           handle: &Handle) -> Result<Self, AccessError> {
        let state = State::read(state_filename)?;
        let key_data = KeyData::read(key_data_filename)?;

        Ok(AccessCodec {cmd: String::from(access_cmd),  duration: duration,
                     handle: handle.clone(), sessions: Rc::new(RefCell::new(HashMap::new())),
                     state: state, key_data: key_data})
    }
}

impl UdpCodec for AccessCodec {
    type In = (SocketAddr, Result<Session, AccessError>, Rc<RefCell<HashMap<String, ClientLease>>>);
    type Out = (SocketAddr, Result<Session, AccessError>, Rc<RefCell<HashMap<String, ClientLease>>>);

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
                match handle_incoming(&sessions, &sess) {
                    SessReqAction::Grant => grant_access(sess, sessions),
                    SessReqAction::Extend => extend_access(sess, sessions),
                    deny =>  println!("{}: {}", addr, deny),
                }
            },
            Err(e) => println!("invalid sess from {:?}: {}", addr, e),
        }
        into.extend(b"thanks");
        addr
    }
}

fn handle_incoming(sessions: &Rc<RefCell<HashMap<String,ClientLease>>>, sess: &Session) -> SessReqAction {
    let client_addr = sess.req_addr.clone();
    let mut sessions_mut = sessions.borrow_mut();
    let lease_info = sessions_mut.entry(client_addr);
    match lease_info {
        Occupied(mut entry) => {
            let lease = entry.get_mut();
            if lease.timeout_start.elapsed().as_secs() < (((sess.duration as f64) * 0.75) as u64) {
                SessReqAction::DenyRenewTooSoon
            } else if lease.leases > 4 {
                SessReqAction::DenyMaxExtensionsReached
            } else if !lease.renew_ok {
                SessReqAction::DenyRenewAlreadyInProgress
            } else {
                lease.timeout_start = Instant::now();
                lease.renew_ok = false;
                lease.leases += 1;
                SessReqAction::Extend
            }
        },
        Vacant(_) => {
            SessReqAction::Grant
        }
    }
}

fn create_lease(sessions: &Rc<RefCell<HashMap<String,ClientLease>>>, client_addr: String) {
    let mut sessions_mut = sessions.borrow_mut();
    sessions_mut.entry(client_addr).or_insert(ClientLease::new());
}

fn  get_timeout_action(sessions: &Rc<RefCell<HashMap<String,ClientLease>>>, sess: &Session)
                       -> TimeoutCompleteAction {
    let client_addr = sess.req_addr.clone();
    let mut sessions_mut = sessions.borrow_mut();
    let lease_info = sessions_mut.entry(client_addr);
    match lease_info {
        Occupied(mut entry) => {
            let lease = entry.get_mut();
            if lease.timeout_start.elapsed().as_secs() >= sess.duration {
                TimeoutCompleteAction::Revoke
            } else {
                lease.renew_ok = true;
                TimeoutCompleteAction::Extend
            }
        },
        Vacant(_) => {
            TimeoutCompleteAction::Unknown
        }
    }
}

fn grant_access(sess: Session, sessions: Rc<RefCell<HashMap<String, ClientLease>>>) {
    println!("new lease for {}", sess.req_addr);
    sess.handle.clone().spawn(
        // 1: Execute the "grant" command.
        Command::new(&sess.cmd).arg("grant")
            .arg(&sess.req_addr)
            .output_async(&sess.handle).map(|output| {(output, sess, sessions)})
        // 2: Create a lease for this client, and start a delay before the "revoke" command.
            .and_then(move |args| {
                let (output, sess, sessions) = args;
                create_lease(&sessions, sess.req_addr.clone());
                print!("start command:\n{}", str::from_utf8(&output.stdout).unwrap());
                Timeout::new(Duration::from_secs(sess.duration), &sess.handle)
                    .unwrap().map(|_| { (sess, sessions) })
            })
        // 3: Continue processing after the timeout.
            .then( |args| {
                let (sess, sessions) = args.unwrap();
                manage_lease(sess, sessions)
            })
    )
}

fn extend_access(sess: Session, sessions: Rc<RefCell<HashMap<String, ClientLease>>>) {
    println!("renew lease for {}", sess.req_addr);
    sess.handle.clone().spawn(
        // 1: start a delay before executing "revoke" command
        Timeout::new(Duration::from_secs(sess.duration), &sess.handle)
            .unwrap().map(|_| { (sess, sessions) })
        // 2: Continue processing after the timeout.
            .then( |args| {
                let (sess, sessions) = args.unwrap();
                manage_lease(sess, sessions)
            })
    )
}

fn manage_lease(sess: Session, sessions: Rc<RefCell<HashMap<String, ClientLease>>>)
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
                                let lease = sessions_mut.get_mut(&sess.req_addr).unwrap();
                                println!("removing {} after {} seconds ", sess.req_addr,
                                         lease.lease_start.elapsed().as_secs());
                            }
                            sessions_mut.remove(&sess.req_addr);
                        }

                        print!("stop command:\n{}", str::from_utf8(&output.stdout).unwrap());
                        future::ok(())
                    }));
            future::ok(())
        },
        TimeoutCompleteAction::Extend => {
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

    let codec = AccessCodec::new(state_filename, key_data_filename, access_cmd,
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
