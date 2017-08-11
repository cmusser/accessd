use std::fmt;


use ::err::AccessError;
use nom::*;

pub const GRANT: u8 = 1;
pub const EXTEND: u8 = 2;
pub const DENY_RENEW_TOO_SOON: u8 = 3;
pub const DENY_MAX_EXTENSION_REACHED: u8 = 4;
pub const DENY__RENEW_ALREADY_IN_PROGRESS: u8 = 5;

pub enum SessReqAction {
    Grant,
    Extend,
    DenyRenewTooSoon,
    DenyMaxExtensionsReached,
    DenyRenewAlreadyInProgress,
}

impl fmt::Display for SessReqAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SessReqAction::Grant => write!(f, "session granted"),
            SessReqAction::Extend => write!(f, "session extended"),
            SessReqAction::DenyRenewTooSoon => write!(f, "request received before renewal window"),
            SessReqAction::DenyMaxExtensionsReached => write!(f, "max session extensions  reached"),
            SessReqAction::DenyRenewAlreadyInProgress => write!(f, "renewal already requested"),
        }
    }
}

fn to_action (i: u8) -> Option<SessReqAction> {
    match i {
        GRANT => Some(SessReqAction::Grant),
        EXTEND => Some(SessReqAction::Extend),
        DENY_RENEW_TOO_SOON => Some(SessReqAction::DenyRenewTooSoon),
        DENY_MAX_EXTENSION_REACHED => Some(SessReqAction::DenyMaxExtensionsReached),
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
    s: sessions >>
    (SessResp { action: a, duration: d, sessions: s })
));


pub struct SessResp {
    action: SessReqAction,
    duration: u64,
    sessions: u8,
}

impl fmt::Display for SessResp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.action {
            ref grant @ SessReqAction::Grant =>
                write!(f, "{} for {} seconds. {} extensions allowed",
                                                grant, self.duration, self.sessions),
            ref extend @ SessReqAction::Extend=>
                write!(f, "{}, {} extension remaining", extend, self.duration),
            ref deny @ _ => write!(f, "{}", deny)
        }
    }
}

impl SessResp {
    pub fn new(action: SessReqAction, duration: u64, sessions: u8) -> Self {
        SessResp { action: action, duration: duration, sessions: sessions }
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
            SessReqAction::Extend => EXTEND,
            SessReqAction::DenyRenewTooSoon => DENY_RENEW_TOO_SOON,
            SessReqAction::DenyMaxExtensionsReached => DENY_MAX_EXTENSION_REACHED,
            SessReqAction::DenyRenewAlreadyInProgress => DENY__RENEW_ALREADY_IN_PROGRESS,
        };

        vec![action]
    }
}
