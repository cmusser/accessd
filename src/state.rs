extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use ::as_hex::u8vec_as_hex;
use ::err::AccessError;
use data_encoding::base16;
use serde::{Deserialize, Deserializer};
use sodiumoxide::crypto::box_::*;

#[derive(Serialize, Deserialize)]
pub struct State {
    #[serde(default, skip)]
    path: PathBuf,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "nonce_from_hex")]
    pub local_nonce: Nonce,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "nonce_from_hex")]
    pub remote_nonce: Nonce,
}

impl State {
    pub fn read(path_str: &str) -> Result<State, AccessError> {
        let path = PathBuf::from(path_str);

        let state = match File::open(&path) {
            Err(why) => {
                println!("couldn't open {} ({}), so resetting nonces",
                         path.display(), why.description());
                let initial: [u8; NONCEBYTES] = [0; NONCEBYTES];
                Ok(State { path: path, local_nonce: Nonce::from_slice(&initial).unwrap(),
                           remote_nonce: Nonce::from_slice(&initial).unwrap()})
            },

            Ok(mut file) => {
                let mut yaml = String::new();
                match file.read_to_string(&mut yaml) {
                    Err(why) => Err(AccessError::FileError(format!("couldn't read {}: {}",
                                                                 path.display(), why.description()))),
                    Ok(_) => {
                        let mut state: State = serde_yaml::from_str(&yaml).unwrap();
                        state.path = path;
                        Ok(state)
                    }
                }
            },
        };
        state
    }

    pub fn write(&self) -> Result<(), AccessError> {

        let mut file = File::create(&self.path).map_err(|e| {
            AccessError::FileError(format!("couldn't create {}: {}",
                                         self.path.display(), e.description()))
        })?;

        let yaml = serde_yaml::to_string(self).map_err(|e| {
            AccessError::SerializeError(e)
        })?;

        file.write_all(yaml.as_bytes()).map_err(|e| {
            AccessError::FileError(format!("couldn't write to {}: {}",
                                         self.path.display(), e.description()))
        })
    }
}

fn nonce_from_hex<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base16::decode(&string.as_bytes()).map_err(|err| Error::custom(err.to_string())))
        .map(|bytes| Nonce::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}
