extern crate access;
extern crate clap;
extern crate sodiumoxide;

use clap::App;
use access::req::{AccessReq, REQ_PORT, ReqType};
use access::err::AccessError;
use access::crypto::*;
use sodiumoxide::crypto::box_;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;

struct AccessClient {
    state: State,
    key_data: KeyData,
    socket: Option<UdpSocket>,
}

impl AccessClient {
    fn new(state_filename: &str, key_data_filename: &str) -> Result<Self, AccessError> {
        let state = State::read(state_filename)?;
        let key_data = KeyData::read(key_data_filename)?;
        Ok(AccessClient {state: state, key_data: key_data, socket: None })
    }

    fn set_remote(&mut self, remote_str: &str, prefer_ipv4: bool) -> Result<&mut Self, AccessError> {
        let mut addrs = format!("{}:{}", remote_str, REQ_PORT)
            .to_socket_addrs()
            .map_err(|e| { AccessError::IoError(e) })?;

        if prefer_ipv4 {
            if let Some(ipv4) = addrs.find(|addr| { addr.is_ipv4() }) {
                let socket = UdpSocket::bind("0.0.0.0:8079").and_then(|socket| {
                    socket.connect(ipv4)?;
                    Ok(socket)
                }).map_err(|e| { AccessError::IoError(e) })?;
                self.socket = Some(socket);
            } else {
                return Err(AccessError::NoIpv4Addr);
            }
        } else {
            let addr = addrs.nth(0).unwrap();
            let bind_addr = if addr.is_ipv4() { "0.0.0.0" } else { "[::]" };
            let socket = UdpSocket::bind(format!("{}:8079", bind_addr)).and_then(|socket| {
                socket.connect(addr)?;
                Ok(socket)
            }).map_err(|e| { AccessError::IoError(e) })?;
            self.socket = Some(socket);
        };

        Ok(self)
    }

    fn send_req(&mut self, client_addr_str: &str) -> Result<(), AccessError> {

        match IpAddr::from_str(client_addr_str) {
            Ok(client_addr) => {
                let msg = AccessReq::new(ReqType::TimedAccess, client_addr).to_msg();
                if let Some(ref socket) = self.socket {
                    self.state.nonce.increment_le_inplace();
                    let mut payload = Vec::new();
                    payload.extend(&self.state.nonce[..]);
                    let encrypted_req_packet = box_::seal(&msg, &self.state.nonce,
                                                          &self.key_data.peer_public,
                                                          &self.key_data.secret);
                    payload.extend(encrypted_req_packet);
                    socket.send(&payload).map_err(|e| { AccessError::IoError(e) })?;
                    println!("access request for {} sent", client_addr);
                    self.state.write()?;
                    let mut buf = [0; 10];
                    match socket.recv(&mut buf) {
                        Ok(received) => {
                            println!("received {} bytes: {}", received, String::from_utf8(buf.to_vec()).unwrap());
                            Ok(())
                        },
                        Err(e) => Err(AccessError::IoError(e)),
                    }
                } else {
                    Err(AccessError::NoRemoteSet)
                }
            },
            Err(e) => Err(AccessError::InvalidAddr(e)),
        }
    }
}

fn main() {

    let matches = App::new("access")
                          .version("1.0")
                          .author("Chuck Musser <cmusser@sonic.net>")
                          .about("Sends access request to host")
                          .args_from_usage(
                              "-a, --addr=[address] 'Specify the client address'
                               -s, --state-file=[filename] 'state file'
                               -k, --key-data-file=[filename] 'key file'
                               -4, --prefer-ipv4 'Prefer IPv4 address'
                              <HOST>              'remote host to access'").get_matches();

    let remote_addr_str = matches.value_of("HOST").unwrap();
    let prefer_ipv4 = matches.is_present("prefer-ipv4");
    let client_addr = matches.value_of("addr").unwrap_or("0.0.0.0");
    let state_filename = matches.value_of("state-file").unwrap_or("access_state.yaml");
    let key_data_filename = matches.value_of("key-data-file").unwrap_or("access_keydata.yaml");

    let client = AccessClient::new(state_filename, key_data_filename);
    match client {
        Ok(mut c) => {
            c.set_remote(remote_addr_str, prefer_ipv4)
                .and_then(|mut c| c.send_req(client_addr))
                .unwrap_or_else(|err| { println!("failed: {}", err) });
        },
        Err(e) => println!("failed: {}", e),
    }
}
