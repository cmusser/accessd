extern crate access;
extern crate clap;
extern crate sodiumoxide;

use clap::App;
use access::req::{SSH_ACCESS, AF_INET, AF_INET6, REQ_PORT};
use access::err::AccessError;
use access::crypto::*;
use sodiumoxide::crypto::box_;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;

struct AccessClient {
    state: State,
    key_data: KeyData,
    remote_addr: Option<SocketAddr>,
}

impl AccessClient {
    fn new(state_filename: &str, key_data_filename: &str) -> Result<Self, AccessError> {
        let state = State::read(state_filename)?;
        let key_data = KeyData::read(key_data_filename)?;
        Ok(AccessClient {state: state, key_data: key_data, remote_addr: None })
    }

    fn set_remote(&mut self, remote_str: &str, prefer_ipv4: bool) -> Result<&mut Self, AccessError> {
        let addrs = format!("{}:{}", remote_str, REQ_PORT).to_socket_addrs();
        match addrs {
            Ok(mut sockaddrs) => {
                if prefer_ipv4 {
                    if let Some(ipv4) = sockaddrs.find(|addr| { addr.is_ipv4() }) {
                        self.remote_addr = Some(ipv4);
                        Ok(self)
                    } else {
                        Err(AccessError::NoIpv4Addr)
                    }
                } else {
                    let r = sockaddrs.nth(0).unwrap();
                    self.remote_addr = Some(r);
                    Ok(self)
                }
            },
            Err(err) => Err(AccessError::IoError(err))
        }
    }

    fn send_req(&mut self, client_addr_str: &str) -> Result<(), AccessError> {

        match IpAddr::from_str(client_addr_str) {
            Ok(addr) => {
                let msg = match addr {
                    IpAddr::V4(addr4) => {
                        let o = addr4.octets();
                        vec![SSH_ACCESS, AF_INET,
                             o[0], o[1], o[2], o[3]]
                    },
                    IpAddr::V6(addr6) => {
                        let o = addr6.octets();
                        vec![SSH_ACCESS, AF_INET6,
                             o[0], o[1], o[2], o[3],
                             o[4], o[5], o[6], o[7],
                             o[8], o[9], o[10], o[11],
                             o[12], o[13], o[14], o[15]]
                    }
                };

                if let Some(addr) = self.remote_addr {
                    let bind_addr = if addr.is_ipv4() {"0.0.0.0"} else {"[::]"};
                    let socket = UdpSocket::bind(format!("{}:8079", bind_addr));
                    match socket {
                        Ok(s) => {
                            self.state.nonce.increment_le_inplace();
                            let mut payload = Vec::new();
                            payload.extend(&self.state.nonce[..]);
                            let encrypted_req_packet = box_::seal(&msg, &self.state.nonce,
                                                                  &self.key_data.peer_public,
                                                                  &self.key_data.secret);
                            payload.extend(encrypted_req_packet);
                            s.send_to(&payload, addr).expect("send_to failed");
                            println!("access request of len {} sent to {:?}", payload.len(),
                                     self.remote_addr);
                            self.state.write()
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
