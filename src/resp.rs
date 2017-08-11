use std::fmt;

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
            SessReqAction::Grant => write!(f, "lease granted"),
            SessReqAction::Extend => write!(f, "lease extended"),
            SessReqAction::DenyRenewTooSoon => write!(f, "request received before renewal window"),
            SessReqAction::DenyMaxExtensionsReached => write!(f, "max session extensions  reached"),
            SessReqAction::DenyRenewAlreadyInProgress => write!(f, "renewal already requested"),
        }
    }
}
