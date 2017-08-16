extern crate access;
extern crate clap;
extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use access::err::AccessError;
use clap::App;
use access::keys::Keypair;
use sodiumoxide::crypto::box_;

fn write_keypair(path_str: &str, keypair: &Keypair) -> Result<(), AccessError> {
     let path = PathBuf::from(path_str);

    let mut file = File::create(&path).map_err(|e| {
            AccessError::FileError(format!("couldn't create {}: {}",
                                         path.display(), e.description()))
        })?;

    let yaml = serde_yaml::to_string(&keypair)
        .map_err(|e| { AccessError::SerializeError(e) })?;

    file.write_all(yaml.as_bytes()) .map_err(|e| {
        AccessError::FileError(format!("couldn't write to {}: {}",
                                       path.display(), e.description()))
    })
}

fn main() {
    let matches = App::new("access-keygen")
        .version("1.0")
        .author("Chuck Musser <cmusser@sonic.net>")
        .about("Generate YAML file with public/private keypair for Nacl authenticated encryption")
        .args_from_usage(
            "<NAME>              'keypair name'").get_matches();

    sodiumoxide::init();
    let keypair_filename = format!("{}_keypair.yaml", matches.value_of("NAME").unwrap());

    let (p, s) = box_::gen_keypair();
    let keypair = Keypair {
        public: p,
        secret: s,
    };

    match write_keypair(&keypair_filename, &keypair) {
        Ok(_) => println!("wrote keypair to {}", keypair_filename),
        Err(e)=> println!("failed to write  {}: {}", keypair_filename, e),
    }
}
