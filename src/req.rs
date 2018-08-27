use std::fmt;
use std::net::*;

use ::err::AccessError;
use serde_cbor::de;
use serde_cbor::ser;

pub const REQ_PORT: u16 = 7387;
pub const TIMED_ACCESS: u8 = 1;

#[derive(Serialize, Deserialize)]
pub enum ReqType {
    TimedAccess
}

impl fmt::Display for ReqType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReqType::TimedAccess => { write!(f, "timed access") }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessReq {
    pub req_type: ReqType,
    pub req_id: u64,
    pub addr: IpAddr,
}

impl SessReq {
    pub fn new(req_type: ReqType, req_id: u64, client_addr: IpAddr) -> Self {
        SessReq {req_type: req_type, req_id: req_id, addr: client_addr }
    }

    pub fn from_msg(msg: &[u8]) -> Result<SessReq, AccessError> {
        de::from_slice(msg).map_err(|e| { AccessError::InvalidCbor(e) })
    }

    pub fn to_msg(&self) -> Result<Vec<u8>, AccessError> {
        ser::to_vec(self).map_err(|e| { AccessError::InvalidCbor(e) })
    }
}

impl fmt::Display for SessReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} for {}", self.req_type, self.addr)
    }
}
