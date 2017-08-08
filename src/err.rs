extern crate serde_yaml;
extern crate sodiumoxide;

use std::fmt;
use std::net::AddrParseError;

use nom::Err;
use sodiumoxide::crypto::box_::NONCEBYTES;

#[derive(Debug)]
pub enum AccessError {
    InvalidNonce,
    ReusedNonce,
    InvalidCiphertext,
    FileError(String),
    SerializeError(serde_yaml::Error),
    NoIpv4Addr,
    NoRemoteSet,
    IoError(::std::io::Error),
    InvalidAddr(AddrParseError),
    ShortReq,
    ShortReqNeeded(usize),
    InvalidReq(Err),
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AccessError::InvalidNonce =>
                write!(f, "Invalid nonce data, make sure data is {} bytes", NONCEBYTES),
            AccessError::ReusedNonce =>
                write!(f, "Received nonce less than current (possible replay)"),
            AccessError::InvalidCiphertext =>
                write!(f, "Ciphertext failed verification"),
            AccessError::FileError(ref str) => write!(f, "{}", str),
            AccessError::SerializeError(ref e) => e.fmt(f),
            AccessError::NoIpv4Addr => write!(f, "No IPv4 address found"),
            AccessError::NoRemoteSet => write!(f, "address of accessd server not set"),
            AccessError::IoError(ref str) => write!(f, "{}", str),
            AccessError::InvalidAddr(ref str) => write!(f, "{}", str),
            AccessError::ShortReq => write!(f, "insufficient data (required unknown)"),
            AccessError::ShortReqNeeded(usize) => write!(f, "Insufficient data: only {} provided)", usize),
            AccessError::InvalidReq(ref err) => write!(f, "{}", err),
        }
    }
}
