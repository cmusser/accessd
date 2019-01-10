extern crate access;
extern crate clap;
extern crate dirs;
extern crate futures;
extern crate sodiumoxide;
extern crate tokio_core;

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use access::req::{SessReq, REQ_PORT, ReqData};
use access::resp::{SessResp};
use access::err::AccessError;
use access::keys::{KeyDataReader, ClientKeyData};
use access::packet;
use access::state::{ClientState, StateManager};
use clap::{App, Arg};
use futures::{Future, Sink, Stream};
use sodiumoxide::crypto::box_::{Nonce, NONCEBYTES};
use sodiumoxide::randombytes::randombytes;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Timeout};

const VERSION: &'static str = "3.0.1";

struct ClientCodec {
    state: ClientState,
    key_data: ClientKeyData,
}

impl ClientCodec {
    fn new(state_filename: &str, key_data_filename: &str) -> Result<Self, AccessError> {
        let state = ClientState::read(state_filename)?;
        let key_data = ClientKeyData::read(key_data_filename)?;
        Ok(ClientCodec {state: state, key_data: key_data })
    }
}

impl UdpCodec for ClientCodec {
    type In = ();
    type Out = (SocketAddr, IpAddr);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {

        match packet::open(buf, &self.key_data.secret, &self.key_data.peer_public) {
            Ok(resp_packet) => {
                match SessResp::from_msg(&resp_packet) {
                    Ok(recv_resp) => println!("{}: {}", addr, recv_resp),
                    Err(e) => println!("couldn't interpret response: {}", e),
                };
            },
            Err(e) => println!("decrypt failed: {}", e),
        }
        Ok(())
    }

    fn encode(&mut self, (remote_addr, client_addr): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        self.state.cur_req_id += 1;
        let nonce: Nonce = Nonce::from_slice(&randombytes(NONCEBYTES)).unwrap();
        into.extend(&nonce[..]);

        match SessReq::new(self.state.cur_req_id, ReqData::TimedAccess(client_addr)).to_msg() {
            Ok(msg) => {
                let encrypted_req_packet = packet::create(&msg, &nonce, &self.key_data.secret,
                                                          &self.key_data.peer_public);
                if let Err(e) = self.state.write() {
                    println!("state file write failed: {}", e)
                }
                into.extend(encrypted_req_packet);
            },
            Err(e) => println!("request creation failed: {}", e),
        }
        remote_addr
    }
}

fn get_remote_addr(remote_str: &str, prefer_ipv4: bool) -> Result<SocketAddr, AccessError> {

    let mut addrs = format!("{}:{}", remote_str, REQ_PORT).to_socket_addrs()
        .map_err(|e| { AccessError::IoError(e) })?;

    let remote_addr = if prefer_ipv4 {
        if let Some(ipv4) = addrs.find(|addr| { addr.is_ipv4() }) {
                ipv4
        } else {
            return Err(AccessError::NoIpv4Addr);
        }
    } else {
        addrs.nth(0).unwrap()
    };

    Ok(remote_addr)
}

fn get_bind_addr_for_remote(remote_addr: &SocketAddr) -> Result<SocketAddr, AccessError> {
    let bind_addr_str = if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else if remote_addr.is_ipv6(){
        "[::]:0"
    } else {
        return Err(AccessError::NoIpv4Addr);
    };

    Ok(bind_addr_str.to_socket_addrs().unwrap().nth(0).unwrap())
}

fn get_client_addr(client_addr_str: &str) -> Result<IpAddr, AccessError> {
    let client_addr = IpAddr::from_str(client_addr_str).map_err(|e| { AccessError::InvalidAddr(e) })?;
    Ok(client_addr)
}

fn run(state_filename: &str, key_data_filename: &str, remote_str: &str,
           prefer_ipv4: bool, client_addr_str: &str) -> Result<(), AccessError> {

    let mut core = Core::new().map_err(|e| { AccessError::IoError(e) })?;
    let handle = core.handle();

    let remote_addr = get_remote_addr(remote_str, prefer_ipv4)?;
    let bind_addr = get_bind_addr_for_remote(&remote_addr)?;
    let client_addr = get_client_addr(client_addr_str)?;
    let codec = ClientCodec::new(state_filename, key_data_filename)?;
    let sock = UdpSocket::bind(&bind_addr, &handle)
        .map_err(|e| { AccessError::IoError(e) })?;
    let (framed_tx, framed_rx) = sock.framed(codec).split();

    let send_req = framed_tx.send((remote_addr, client_addr))
        .and_then(|_| { framed_rx.take(1).into_future().map_err(|(e,_)| e) })
        .select2(Timeout::new(Duration::from_secs(5), &handle).unwrap()
                 .then(|t| { println!("no response from {}", remote_addr); t }));

    Ok(drop(core.run(send_req)))
}

fn main() {
    let default_state_filename = format!("{}/.access/state.yaml",
                                         dirs::home_dir().unwrap().display() );
    let default_key_data_filename = format!("{}/.access/keydata.yaml",
                                         dirs::home_dir().unwrap().display());
    let matches = App::new("access")
                          .version(VERSION)
                          .author("Chuck Musser <cmusser@sonic.net>")
                          .about("Sends access request to host")
                          .arg(Arg::with_name("address").empty_values(false)
                             .short("a").long("addr").default_value("0.0.0.0")
                             .help("Specify the client address"))
                          .arg(Arg::with_name("state-file").empty_values(false)
                             .short("s").long("state-file").default_value(&default_state_filename)
                             .help("Path to state file"))
                          .arg(Arg::with_name("key-data-file").empty_values(false)
                             .short("k").long("key-data-file").default_value(&default_key_data_filename)
                             .help("Path to key data file"))
                          .arg(Arg::with_name("prefer-ipv4")
                             .short("4").long("prefer-ipv4")
                             .help("Prefer IPv4 address"))
                          .arg(Arg::with_name("HOST")
                             .required(true)
                             .help("Remote host to access"))
                             .get_matches();

    if let Err(e) = run(matches.value_of("state-file").unwrap(),
                        matches.value_of("key-data-file").unwrap(),
                        matches.value_of("HOST").unwrap(),
                        matches.is_present("prefer-ipv4"),
                        matches.value_of("address").unwrap()) {
        println!("failed: {}", e);
    }
}
