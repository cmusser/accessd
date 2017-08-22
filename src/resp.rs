use std::fmt;

use ::err::AccessError;
use serde_cbor::de;
use serde_cbor::ser;

#[derive(Serialize, Deserialize)]
pub enum SessReqAction {
    Grant,
    Renew,
    DenyRenewTooSoon,
    DenyMaxRenewalsReached,
    DenyRenewAlreadyInProgress,
}

impl fmt::Display for SessReqAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SessReqAction::Grant => write!(f, "session granted"),
            SessReqAction::Renew => write!(f, "session renewed"),
            SessReqAction::DenyRenewTooSoon => write!(f, "request received before renewal window"),
            SessReqAction::DenyMaxRenewalsReached => write!(f, "max session renewals reached"),
            SessReqAction::DenyRenewAlreadyInProgress => write!(f, "renewal already requested"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessResp {
    pub action: SessReqAction,
    duration: u64,
    renewals_remaining: u8,
}

impl fmt::Display for SessResp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.action {
            ref grant @ SessReqAction::Grant =>
                write!(f, "{} for {} seconds. {} renewals allowed.",
                                                grant, self.duration, self.renewals_remaining),
            ref renew @ SessReqAction::Renew =>
                write!(f, "{} for {} seconds. {} renewals remaining.",
                       renew, self.duration, self.renewals_remaining),
            ref too_soon @ SessReqAction::DenyRenewTooSoon =>
                write!(f, "{}, renewal ok in {} seconds.",
                       too_soon, self.duration),

            ref deny @ _ => write!(f, "{}", deny)
        }
    }
}

impl SessResp {
    pub fn new(action: SessReqAction, duration: u64, renewals_remaining: u8) -> Self {
        SessResp { action: action, duration: duration, renewals_remaining: renewals_remaining }
    }

    pub fn from_msg(msg: &[u8]) -> Result<SessResp, AccessError> {
        de::from_slice(msg).map_err(|e| { AccessError::InvalidCbor(e) })
    }

    pub fn to_msg(&self) -> Result<Vec<u8>, AccessError> {
        ser::to_vec(self).map_err(|e| { AccessError::InvalidCbor(e) })
    }
}
