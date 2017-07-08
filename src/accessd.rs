 #[macro_use]
#[allow(unused)]
extern crate clap;
extern crate access;
extern crate tokio_core;
extern crate tokio_process;
extern crate futures;

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

use clap::App;
use futures::{future, Future, Stream};
use access::req::AccessReq;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_process::CommandExt;

enum LeaseReqAction {
    Grant,
    Extend,
    Deny(String),
}

enum TimeoutCompleteAction {
    Revoke,
    Extend,
    Unknown,
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

pub struct AccessTask {
    cmd: String,
    duration: u64,
    req_addr: String,
    handle: Handle,
}

impl AccessTask {
    fn new (cmd: &String, duration: u64, req_addr: IpAddr, handle: &Handle) -> Self {
        AccessTask {cmd: cmd.clone(), duration: duration,
                    req_addr: req_addr.to_string(), handle: handle.clone()}
    }
}

 pub struct AccessCodec {
     cmd: String,
     duration: u64,
     handle: Handle,
     addrs: Rc<RefCell<HashMap<String,ClientLease>>>,
}

impl UdpCodec for AccessCodec {
    type In = (SocketAddr, AccessTask, Rc<RefCell<HashMap<String, ClientLease>>>);
    type Out = (SocketAddr, Vec<u8>);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        let task =
        if let Ok(recv_req)  = AccessReq::from_msg(buf) {
            if recv_req.addr.is_unspecified() {
                AccessTask::new(&self.cmd, self.duration, addr.ip(), &self.handle)
            } else {
                AccessTask::new(&self.cmd, self.duration, recv_req.addr, &self.handle)
            }
        } else {
            AccessTask::new(&self.cmd, self.duration, AccessReq::blank().addr, &self.handle)
        };

        Ok((*addr, task, self.addrs.clone()))
    }

    fn encode(&mut self, (addr, buf): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        into.extend(buf);
        addr
    }
}

fn handle_incoming(addrs: &Rc<RefCell<HashMap<String,ClientLease>>>, client_addr: String) -> LeaseReqAction {
    let mut hm = addrs.borrow_mut();
    let lease_info = hm.entry(client_addr);
    match lease_info {
        Occupied(mut entry) => {
            let lease = entry.get_mut();
            if lease.timeout_start.elapsed().as_secs() < ((5.0 * 0.75) as u64) {
                LeaseReqAction::Deny(String::from("request received before renewal window"))
            } else if lease.leases > 4 {
                LeaseReqAction::Deny(String::from("max consecutive leases reached"))
            } else if !lease.renew_ok {
                LeaseReqAction::Deny(String::from("renewal already requested"))
            } else {
                lease.timeout_start = Instant::now();
                lease.renew_ok = false;
                lease.leases += 1;
                LeaseReqAction::Extend
            }
        },
        Vacant(_) => {
            LeaseReqAction::Grant
        }
    }
}

fn create_lease(addrs: &Rc<RefCell<HashMap<String,ClientLease>>>, client_addr: String) {
    let mut hm = addrs.borrow_mut();
    hm.entry(client_addr).or_insert(ClientLease::new());
}

fn  get_timeout_action(addrs: &Rc<RefCell<HashMap<String,ClientLease>>>, client_addr: String)
                 -> TimeoutCompleteAction {
    let mut hm = addrs.borrow_mut();
    let lease_info = hm.entry(client_addr);
    match lease_info {
        Occupied(mut entry) => {
            let lease = entry.get_mut();
            if lease.timeout_start.elapsed().as_secs() >= 5 {
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

fn grant_access(t: AccessTask, addrs: Rc<RefCell<HashMap<String, ClientLease>>>) {
    println!("new lease for {}", t.req_addr);
    t.handle.clone().spawn(
        // 1: Execute the "grant" command.
        Command::new(&t.cmd).arg("grant")
            .arg(&t.req_addr)
            .output_async(&t.handle).map(|o| {(o, t, addrs)})
        // 2: Create a lease for this client, and start a delay before the "revoke" command.
            .and_then(move |args| {
                let (o, t, addrs) = args;
                create_lease(&addrs, t.req_addr.clone());
                print!("start command:\n{}", str::from_utf8(&o.stdout).unwrap());
                Timeout::new(Duration::from_secs(t.duration), &t.handle)
                    .unwrap().map(|_| { (t, addrs) })
            })
        // 3: Continue processing after the timeout.
            .then( |args| {
                let (t, addrs) = args.unwrap();
                manage_lease(t, addrs)
            })
    )
}

fn extend_access(t: AccessTask, addrs: Rc<RefCell<HashMap<String, ClientLease>>>) {
    println!("renew lease for {}", t.req_addr);
    t.handle.clone().spawn(
        // 1: start a delay before executing "revoke" command
        Timeout::new(Duration::from_secs(t.duration), &t.handle)
            .unwrap().map(|_| { (t, addrs) })
        // 2: Continue processing after the timeout.
            .then( |args| {
                let (t, addrs) = args.unwrap();
                manage_lease(t, addrs)
            })
    )
}

fn manage_lease(t: AccessTask, addrs: Rc<RefCell<HashMap<String, ClientLease>>>)
                  -> futures::future::FutureResult<(), ()> {

    match get_timeout_action(&addrs, t.req_addr.clone()) {
        TimeoutCompleteAction::Revoke => {
            t.handle.clone().spawn(
                Command::new(&t.cmd).arg("revoke")
                    .arg(&t.req_addr)
                    .output_async(&t.handle).map(|o| {(o, t, addrs)})
                    .then(move |args| {
                        let (o, t, addrs) = args.unwrap();
                        {
                            let mut hm = addrs.borrow_mut();
                            {
                                let lease = hm.get_mut(&t.req_addr).unwrap();
                                println!("removing {} after {} seconds ", t.req_addr,
                                         lease.lease_start.elapsed().as_secs());
                            }
                            hm.remove(&t.req_addr);
                        }

                        print!("stop command:\n{}", str::from_utf8(&o.stdout).unwrap());
                        future::ok(())
                    }));
            future::ok(())
        },
        TimeoutCompleteAction::Extend => {
            future::ok(())
        },
        TimeoutCompleteAction::Unknown => {
            println!("{} unknown", t.req_addr);
            future::ok(())
        }
    }
}

fn main() {

    let matches = App::new("accessd")
        .version("1.0")
        .author("Chuck Musser <cmusser@sonic.net>")
        .about("Grant access to host")
        .args_from_usage(
            "-d, --duration=[seconds] 'duration of access period (default: 5)'
                              <CMD>              'command to grant/revoke access'").get_matches();

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let kc = AccessCodec {cmd: String::from(matches.value_of("CMD").unwrap()),
                         duration: matches.value_of("duration").unwrap_or("5")
                         .parse::<u64>().unwrap(),
                         handle: handle.clone(),
                         addrs: Rc::new(RefCell::new(HashMap::new()))};

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let sock = UdpSocket::bind(&addr, &handle).unwrap();
    let (_, incoming) = sock.framed(kc).split();

    let incoming = incoming.for_each(|(addr, task, addrs)| {
        match handle_incoming(&addrs, task.req_addr.clone()) {
            LeaseReqAction::Grant => {
                grant_access(task, addrs)
            },
            LeaseReqAction::Extend => {
                extend_access(task, addrs)
            },
            LeaseReqAction::Deny(msg) =>  { println!("no action for {}: {}", addr, msg); },
        }

        future::ok(())
    });

    drop(core.run(incoming));
}
