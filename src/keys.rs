extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use data_encoding::base16;
use err::AccessError;
use serde::{Deserialize, Deserializer, Serializer};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "seckey_from_hex")]
    pub secret: SecretKey,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "pubkey_from_hex")]
    pub public: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct ClientKeyData {
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "seckey_from_hex")]
    pub secret: SecretKey,
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "pubkey_from_hex")]
    pub peer_public: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct ServerKeyData {
    #[serde(serialize_with = "u8vec_as_hex", deserialize_with = "seckey_from_hex")]
    pub secret: SecretKey,
    #[serde(
        serialize_with = "ser_public_keys",
        deserialize_with = "de_public_keys"
    )]
    pub peer_public_keys: HashMap<String, PublicKey>,
}

pub trait KeyDataReader {
    type Item;

    fn read(path_str: &str) -> Result<Self::Item, AccessError>
    where
        for<'de> <Self as KeyDataReader>::Item: Deserialize<'de>,
    {
        let path = Path::new(&path_str);

        match File::open(&path) {
            Err(why) => Err(AccessError::FileError(format!(
                "couldn't open {} ({})",
                path.display(),
                why.description()
            ))),

            Ok(mut file) => {
                let mut yaml = String::new();
                match file.read_to_string(&mut yaml) {
                    Err(why) => Err(AccessError::FileError(format!(
                        "couldn't read {}: {}",
                        path.display(),
                        why.description()
                    ))),
                    Ok(_) => serde_yaml::from_str(&yaml).map_err(AccessError::SerializeError),
                }
            }
        }
    }
}

impl KeyDataReader for ClientKeyData {
    type Item = Self;
}
impl KeyDataReader for ServerKeyData {
    type Item = Self;
}

pub fn u8vec_as_hex<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base16::encode(&data.as_ref()))
}

fn pubkey_from_hex<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
            base16::decode(&string.as_bytes()).map_err(|err| Error::custom(err.to_string()))
        })
        .map(|bytes| PublicKey::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}

fn seckey_from_hex<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
            base16::decode(&string.as_bytes()).map_err(|err| Error::custom(err.to_string()))
        })
        .map(|bytes| SecretKey::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}

fn ser_public_keys<S>(
    peer_public: &HashMap<String, PublicKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[derive(Serialize)]
    struct Wrapper<'a>(#[serde(serialize_with = "u8vec_as_hex")] &'a PublicKey);

    let map = peer_public.iter().map(|(k, v)| (k, Wrapper(v)));
    serializer.collect_map(map)
}

fn de_public_keys<'de, D>(deserializer: D) -> Result<HashMap<String, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "pubkey_from_hex")] PublicKey);

    let v = HashMap::<String, Wrapper>::deserialize(deserializer)?;
    Ok(v.into_iter().map(|(k, Wrapper(v))| (k, v)).collect())
}
