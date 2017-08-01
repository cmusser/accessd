extern crate access;
extern crate clap;
extern crate serde_yaml;
extern crate sodiumoxide;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use clap::App;
use access::crypto::Keypair;
use sodiumoxide::crypto::box_;

fn write_keypair(path: &Path, keypair: &Keypair) {
    let display = path.display();

    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}",
                           display, why.description()),
        Ok(file) => file,
    };

    let yaml = serde_yaml::to_string(&keypair).unwrap();
    match file.write_all(yaml.as_bytes()) {
        Err(why) => {
            panic!("couldn't write to {}: {}", display,
                                               why.description())
        },
        Ok(_) => println!("successfully wrote keypair to {}", display),
    }
}

fn main() {
    let matches = App::new("access-keygen")
        .version("1.0")
        .author("Chuck Musser <cmusser@sonic.net>")
        .about("Generate YAML file with public/private keypair for Nacl authenticated encryption")
        .args_from_usage(
            "<NAME>              'keypair name'").get_matches();
    
    sodiumoxide::init();
    let keypair_name = format!("{}_keypair.yaml", matches.value_of("NAME").unwrap());
    let path = Path::new(&keypair_name);

    let (p, s) = box_::gen_keypair();
    let keypair = Keypair {
        public: p,
        secret: s,
    };
    write_keypair(path, &keypair)
}
