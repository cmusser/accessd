use std::fmt;

use ::err::AccessError;
use byteorder::{BigEndian, WriteBytesExt};
use nom::*;

pub const GRANT: u8 = 1;
pub const RENEW: u8 = 2;
pub const DENY_RENEW_TOO_SOON: u8 = 3;
pub const DENY_MAX_RENEWALS_REACHED: u8 = 4;
pub const DENY__RENEW_ALREADY_IN_PROGRESS: u8 = 5;

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

fn to_action (i: u8) -> Option<SessReqAction> {
    match i {
        GRANT => Some(SessReqAction::Grant),
        RENEW => Some(SessReqAction::Renew),
        DENY_RENEW_TOO_SOON => Some(SessReqAction::DenyRenewTooSoon),
        DENY_MAX_RENEWALS_REACHED => Some(SessReqAction::DenyMaxRenewalsReached),
        DENY__RENEW_ALREADY_IN_PROGRESS => Some(SessReqAction::DenyRenewAlreadyInProgress),
        _ => None,
    }
}

named!(action <&[u8], SessReqAction>, map_opt!(be_u8, to_action));
named!(duration <&[u8], u64>, call!(be_u64));
named!(sessions <&[u8], u8>, call!(be_u8));

named!(resp_msg <&[u8], SessResp>, do_parse!(
    a: action >>
    d: duration >>
    r: sessions >>
    (SessResp { action: a, duration: d, renewals_remaining: r })
));


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
        match resp_msg(&msg) {
            IResult::Done(_, resp) => { Ok(resp) },
            IResult::Incomplete(needed) => {
                match needed {
                    Needed::Unknown => Err(AccessError::ShortReq),
                    Needed::Size(s) =>  Err(AccessError::ShortReqNeeded(s))
                }
            },
            IResult::Error(error) => Err(AccessError::InvalidReq(error)) ,
        }
    }

    pub fn to_msg(&self) -> Vec<u8> {
        let action: u8 = match self.action {
            SessReqAction::Grant => GRANT,
            SessReqAction::Renew => RENEW,
            SessReqAction::DenyRenewTooSoon => DENY_RENEW_TOO_SOON,
            SessReqAction::DenyMaxRenewalsReached => DENY_MAX_RENEWALS_REACHED,
            SessReqAction::DenyRenewAlreadyInProgress => DENY__RENEW_ALREADY_IN_PROGRESS,
        };

        let mut msg = Vec::with_capacity(10);
        msg.push(action);
        let mut wtr = vec![];
        wtr.write_u64::<BigEndian>(self.duration).unwrap();
        msg.extend_from_slice(&wtr);
        msg.push(self.renewals_remaining);
        msg
    }
}
