extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use data_encoding::{base16};
use serde::{Serializer, Deserialize, Deserializer};
use sodiumoxide::crypto::box_::*;

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    #[serde(serialize_with = "seckey_as_hex", deserialize_with = "seckey_from_hex")]
    pub secret: SecretKey,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "pubkey_from_hex")]
    pub public: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct KeyData {
    #[serde(serialize_with = "seckey_as_hex", deserialize_with = "seckey_from_hex")]
    pub secret: SecretKey,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "pubkey_from_hex")]
    pub peer_public: PublicKey,
}

impl KeyData {
    pub fn read(path_str: String) -> KeyData {
        let path = Path::new(&path_str);

        match File::open(&path) {
            Err(why) => {
                panic!("couldn't open {} ({})",
                         path.display(), why.description());
            },

            Ok(mut file) => {
                let mut yaml = String::new();
                match file.read_to_string(&mut yaml) {
                    Err(why) => panic!("couldn't read {}: {}", path.display(),
                                       why.description()),
                    Ok(_) => serde_yaml::from_str(&yaml).unwrap(),
                }
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct State {
    #[serde(default, skip)]
    path: PathBuf,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "nonce_from_hex")]
    pub nonce: Nonce,
}

impl State {
    pub fn read(path_str: String) -> State {
        let path = PathBuf::from(path_str);

        let state = match File::open(&path) {
            Err(why) => {
                println!("couldn't open {} ({}), so resetting nonce",
                         path.display(), why.description());
                let initial: [u8; NONCEBYTES] = [0; NONCEBYTES];
                State { path: path, nonce: Nonce::from_slice(&initial).unwrap() }
            },

            Ok(mut file) => {
                let mut yaml = String::new();
                match file.read_to_string(&mut yaml) {
                    Err(why) => panic!("couldn't read {}: {}", path.display(),
                                       why.description()),
                    Ok(_) => {
                        let mut state: State = serde_yaml::from_str(&yaml).unwrap();
                        state.path = path;
                        state
                    }
                }
            },
        };
        state
    }

    pub fn write(&self) {

        let mut file = match File::create(&self.path) {
            Err(why) => panic!("couldn't create {}: {}",
                               self.path.display(), why.description()),
            Ok(file) => file,
        };

        let yaml = serde_yaml::to_string(self).unwrap();
        match file.write_all(yaml.as_bytes()) {
            Err(why) => {
                panic!("couldn't write to {}: {}", self.path.display(),
                       why.description())
            },
            Ok(_) => {},
        }
    }
}

fn u8vec_as_hex<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: AsRef<[u8]>,
          S: Serializer
{
    serializer.serialize_str(&base16::encode(&data.as_ref()))
}

fn seckey_as_hex<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    serializer.serialize_str(&base16::encode(&key[..]))
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

fn pubkey_from_hex<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base16::decode(&string.as_bytes()).map_err(|err| Error::custom(err.to_string())))
        .map(|bytes| PublicKey::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}

fn seckey_from_hex<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base16::decode(&string.as_bytes()).map_err(|err| Error::custom(err.to_string())))
        .map(|bytes| SecretKey::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}
