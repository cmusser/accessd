extern crate clap;
extern crate access;

use clap::App;
use access::req::{SSH_ACCESS, AF_INET, AF_INET6};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;

fn main() {

    let matches = App::new("access")
                          .version("1.0")
                          .author("Chuck Musser <cmusser@sonic.net>")
                          .about("Sends access request to host")
                          .args_from_usage(
                              "-a, --addr=[address] 'Specify the client address'
                               -4, --prefer-ipv4 'Prefer IPv4 address'
                              <HOST>              'remote host to access'").get_matches();

    let bind_addr: &str;
    let remote_addr: SocketAddr;
    let remote_str = matches.value_of("HOST").unwrap();
    match format!("{}:8080", remote_str).to_socket_addrs() {
        Ok(mut sockaddrs) => {
            if matches.is_present("prefer-ipv4") {
                if let Some(ipv4) = sockaddrs.find(|addr| { addr.is_ipv4() }) {
                    remote_addr = ipv4;
                    bind_addr = "0.0.0.0";
                } else {
                    println!("No IPv4 address found for {}", remote_str);
                    ::std::process::exit(1);
                }
            } else {
                remote_addr = sockaddrs.nth(0).unwrap();
                if remote_addr.is_ipv4() {
                    bind_addr = "0.0.0.0";
                } else {
                    bind_addr = "[::]";
                }
            }
        },
        Err(err) => {
            println!("{}: {}", err, remote_str);
            ::std::process::exit(1);
        }
    };

    let client_addr_str = matches.value_of("addr").unwrap_or("0.0.0.0");
    let msg = match IpAddr::from_str(client_addr_str).unwrap() {
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

    let s = UdpSocket::bind(format!("{}:8079", bind_addr)).expect("bind failed");
    match s.take_error() {
        Ok(Some(error)) => println!("UdpSocket error: {:?}", error),
        Ok(None) => {
            s.send_to(&msg, remote_addr).expect("send_to failed");
            println!("access request sent to {} ({})", remote_str, remote_addr);
        }
        Err(error) => println!("UdpSocket.take_error failed: {:?}", error)
    }
}
