extern crate access;
extern crate clap;
extern crate futures;
extern crate sodiumoxide;
extern crate tokio_core;

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use access::req::{SessReq, REQ_PORT, ReqType};
use access::resp::{SessResp};
use access::err::AccessError;
use access::keys::KeyData;
use access::packet;
use access::state::State;
use clap::App;
use futures::{Future, Sink, Stream};
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::{Core, Timeout};

struct ClientCodec {
    state: State,
    key_data: KeyData,
}

impl ClientCodec {
    fn new(state_filename: &str, key_data_filename: &str) -> Result<Self, AccessError> {
        let state = State::read(state_filename)?;
        let key_data = KeyData::read(key_data_filename)?;
        Ok(ClientCodec {state: state, key_data: key_data })
    }
}

impl UdpCodec for ClientCodec {
    type In = ();
    type Out = (SocketAddr, IpAddr);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {

        match packet::open(buf, &mut self.state, &self.key_data) {
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
        self.state.local_nonce.increment_le_inplace();
        into.extend(&self.state.local_nonce[..]);

        match SessReq::new(ReqType::TimedAccess, client_addr).to_msg() {
            Ok(msg) => {
                let encrypted_req_packet = packet::create(&msg, &mut self.state,
                                                              &self.key_data);
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
                                         std::env::home_dir().unwrap().display());
    let default_key_data_filename = format!("{}/.access/keydata.yaml",
                                         std::env::home_dir().unwrap().display());
    let matches = App::new("access")
                          .version("1.0.0")
                          .author("Chuck Musser <cmusser@sonic.net>")
                          .about("Sends access request to host")
                          .args_from_usage(
                              "-a, --addr=[address] 'Specify the client address'
                               -s, --state-file=[filename] 'state file'
                               -k, --key-data-file=[filename] 'key file'
                               -4, --prefer-ipv4 'Prefer IPv4 address'
                              <HOST>              'remote host to access'").get_matches();

    let remote_str = matches.value_of("HOST").unwrap();
    let prefer_ipv4 = matches.is_present("prefer-ipv4");
    let client_addr_str = matches.value_of("addr").unwrap_or("0.0.0.0");
    let state_filename = matches.value_of("state-file").unwrap_or(&default_state_filename);
    let key_data_filename = matches.value_of("key-data-file").unwrap_or(&default_key_data_filename);

    if let Err(e) = run(state_filename, key_data_filename, remote_str, prefer_ipv4,
                        client_addr_str) {
        println!("failed: {}", e);
    }
}
