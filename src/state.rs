extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use ::err::AccessError;

#[derive(Serialize, Deserialize)]
pub struct State {
    #[serde(default, skip)]
    path: PathBuf,
    pub cur_req_id: u64,
}

impl State {
    pub fn read(path_str: &str) -> Result<State, AccessError> {
        let path = PathBuf::from(path_str);

        let state = match File::open(&path) {
            Err(why) => {
                println!("couldn't open {} ({}), so resetting nonces",
                         path.display(), why.description());
                Ok(State { path: path, cur_req_id: 0 })
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
