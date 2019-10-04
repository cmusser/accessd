use std::fmt;
use std::net::*;

use err::AccessError;
use serde_cbor::de;
use serde_cbor::ser;

pub const REQ_PORT: u16 = 7387;
pub const TIMED_ACCESS: u8 = 1;

#[derive(Serialize, Deserialize)]
pub enum ReqData {
    TimedAccess(IpAddr),
}

impl fmt::Display for ReqData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReqData::TimedAccess(ip_addr) => write!(f, "timed access for {}", ip_addr),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessReq {
    pub req_id: u64,
    pub req_data: ReqData,
}

impl SessReq {
    pub fn new(req_id: u64, req_data: ReqData) -> Self {
        SessReq { req_id, req_data }
    }

    pub fn from_msg(msg: &[u8]) -> Result<SessReq, AccessError> {
        de::from_slice(msg).map_err(AccessError::InvalidCbor)
    }

    pub fn to_msg(&self) -> Result<Vec<u8>, AccessError> {
        ser::to_vec(self).map_err(AccessError::InvalidCbor)
    }
}

impl fmt::Display for SessReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.req_data)
    }
}
