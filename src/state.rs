extern crate serde_yaml;
extern crate sodiumoxide;

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::marker::Sized;
use std::io::prelude::*;
use std::path::PathBuf;

use ::err::AccessError;

use serde::{Serialize,Deserialize};

pub trait StateManager
where Self: Serialize, Self: Sized, for<'de> Self: Deserialize<'de>
{
    type Item;

    fn new_at_path(path: PathBuf) -> Self;
    fn path(&self) -> &PathBuf;
    fn set_path(&mut self, path: PathBuf);
    
    fn write(&self) -> Result<(), AccessError> {

        let mut file = File::create(&self.path()).map_err(|e| {
            AccessError::FileError(format!("couldn't create {}: {}",
                                         self.path().display(), e.description()))
        })?;

        let yaml = serde_yaml::to_string(self).map_err(|e| {
            AccessError::SerializeError(e)
        })?;

        file.write_all(yaml.as_bytes()).map_err(|e| {
            AccessError::FileError(format!("couldn't write to {}: {}",
                                         self.path().display(), e.description()))
        })
    }

    fn read(path_str: &str) -> Result<Self, AccessError>
    {
        let path = PathBuf::from(path_str);

        let state = match File::open(&path) {
            Err(why) => {
                println!("couldn't open {} ({}), so resetting nonces",
                         path.display(), why.description());
                Ok(Self::new_at_path(path))
            },

            Ok(mut file) => {
                let mut yaml = String::new();
                match file.read_to_string(&mut yaml) {
                    Err(why) => Err(AccessError::FileError(format!("couldn't read {}: {}",
                                                                 path.display(), why.description()))),
                    Ok(_) => {
                        match serde_yaml::from_str::<Self>(&yaml) {
                            Ok(mut state) => {
                                state.set_path(path);
                                Ok(state)
                            },
                            Err(e) =>  Err(AccessError::FileError(format!("couldn't parse {}: {}",
                                                                      path_str, e.description())))
                        }
                    }
                }
            },
        };
        state
    }
}

#[derive(Serialize, Deserialize)]
pub struct ClientState {
    #[serde(default, skip)]
    path: PathBuf,
    pub cur_req_id: u64,
}

impl StateManager for ClientState {
    type Item = Self;
    fn new_at_path(path: PathBuf) -> Self { Self { path: path, cur_req_id: 0 }}
    fn path(&self) -> &PathBuf { &self.path }
    fn set_path(&mut self, path: PathBuf) { self.path = path }
}

#[derive(Serialize, Deserialize)]
pub struct ServerState {
    #[serde(default, skip)]
    path: PathBuf,
    pub cur_req_ids: HashMap<String, u64>,
}

impl StateManager for ServerState {
    type Item = Self;
    fn new_at_path(path: PathBuf) -> Self { Self { path: path, cur_req_ids: HashMap::new() } }
    fn path(&self) -> &PathBuf { &self.path }
    fn set_path(&mut self, path: PathBuf) { self.path = path }
}
