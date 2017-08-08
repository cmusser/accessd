use std::fmt;
use std::net::*;
use nom::*;

pub const REQ_PORT: u16 = 7387;
pub const SSH_ACCESS: u8 = 1;
pub const AF_INET: u8 = 1;
pub const AF_INET6: u8 = 2;

pub enum ReqType {
    TimedAccess
}

impl fmt::Display for ReqType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReqType::TimedAccess => { write!(f, "SSH access") }
        }
    }
}

fn to_req_type (i: u8) -> Option<ReqType> {
    match i {
        SSH_ACCESS => Some(ReqType::TimedAccess),
        _ => None,
    }
}

pub enum AddrFamily {
    V4,
    V6
}

fn to_addr_family (i: u8) -> Option<AddrFamily> {
    match i {
        AF_INET => Some(AddrFamily::V4),
        AF_INET6 => Some(AddrFamily::V6),
        _ => None,
    }
}

fn u8vec_to_ipv4(b: &[u8]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

fn u16vec_to_ipv6(b: Vec<u16>) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]))
}

named!(req_type <&[u8], ReqType>, map_opt!(be_u8, to_req_type));
named!(addr_family <&[u8], AddrFamily>, map_opt!(be_u8, to_addr_family));
named!(addr4 <&[u8], IpAddr>, map!(take!(4), u8vec_to_ipv4));
named!(addr6 <&[u8], IpAddr>, map!(count!(be_u16, 8), u16vec_to_ipv6));
named!(addr <&[u8], IpAddr>, switch!(addr_family,
                                     AddrFamily::V4 => call!(addr4) |
                                     AddrFamily::V6 => call!(addr6))
);
named!(access_msg <&[u8], AccessReq>, do_parse!(
    t: req_type >>
    a: addr >>
    (AccessReq {req_type: t, addr: a})
));

pub struct AccessReq {
    pub req_type: ReqType,
    pub addr: IpAddr,
}

impl AccessReq {
    pub fn from_msg(msg: &[u8]) -> Result<AccessReq, String> {
        match access_msg(&msg) {
            IResult::Done(_, req) => { Ok(req) },
            IResult::Incomplete(needed) => {
                match needed {
                    Needed::Unknown => { Err(format!("insufficient data (required unknown)")) },
                    Needed::Size(s) => { Err(format!("Only {:?} provided", s)) },
                }
            },
            IResult::Error(error) => {Err(format!("{}", error)) },
        }
    }

    pub fn blank() -> AccessReq {
        AccessReq {req_type: ReqType::TimedAccess,
                  addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))}
    }
}

impl fmt::Display for AccessReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} for {}", self.req_type, self.addr)
    }
}

#[test]
fn v4_access_msg() {
    let msg = vec![SSH_ACCESS, AF_INET, 127, 0, 0, 1];
    AccessReq::from_msg(&msg).unwrap();
}

#[test]
fn v6_access_msg() {
    let msg = vec![SSH_ACCESS, AF_INET6,
                   0x20, 0x01, 0x4, 0x70,
                   0x1f, 0x05, 0x2, 0x04,
                   0x85, 0x3c, 0xa3, 0x3c,
                   0xbb, 0x33, 0xa8, 0xf3];
    AccessReq::from_msg(&msg).unwrap();
}

#[test]
#[should_panic(expected = "Only 5 provided")]
fn v4_access_msg_2short() {
    let msg = vec![SSH_ACCESS, AF_INET, 127, 0, 0];
    AccessReq::from_msg(&msg).unwrap();
}

#[test]
#[should_panic(expected = "Only 15 provided")]
fn v6_access_msg_2short() {
    let msg = vec![SSH_ACCESS, AF_INET6,
                   0x20, 0x01, 0x4, 0x70,
                   0x1f, 0x05, 0x2, 0x04,
                   0x85, 0x3c, 0xa3, 0x3c,
                   0xbb];
    AccessReq::from_msg(&msg).unwrap();
}

#[test]
#[should_panic(expected = "Map on Option")]
fn v4_invalid_req_msg() {
    let msg = vec![42, AF_INET, 127, 0, 0, 1];
    AccessReq::from_msg(&msg).unwrap();
}

#[test]
#[should_panic(expected = "Switch")]
fn invalid_access_msg() {
    let msg = vec![SSH_ACCESS, 42,
                   0x20, 0x01, 0x4, 0x70,
                   0x1f, 0x05, 0x2, 0x04,
                   0x85, 0x3c, 0xa3, 0x3c,
                   0xbb, 0x33, 0xa8, 0xf3];
    AccessReq::from_msg(&msg).unwrap();
}
