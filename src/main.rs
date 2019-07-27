#[macro_use]
extern crate clap;

mod config;
mod credential_extractor;

use config::Config;
use clap::App;
use credential_extractor::{AuthorizationExtractor, BasicAuthExtractor, CredentialExtractor};
use std::fs::File;
use std::io::{BufRead, BufReader};

use std::process::exit;

fn main() {

    let shell = "zsh";
    let _config = get_config();

    match (
        CredentialExtractor::new(),
        File::open(format!("/Users/matthewrick/.{}_history", shell)),
    ) {
        (Ok(extractor), Ok(history)) => for result in BufReader::new(history).lines() {
            match result {
                Err(e) => println!("Error reading line: {}", e),
                Ok(ref line) if is_curl_command(line) => {
                    match (
                        extractor.get_authorization(line),
                        extractor.get_basic_auth(line),
                    ) {
                        (Some((username, password)), _) => println!("{}:{}", username, password),
                        (_, Some((auth_type, authentication))) => println!("Authorization: {} {}", auth_type, authentication),
                        (_, _) => ()
                    }
                },
                Ok(_) => (),
            }
        },
        (Err(msg), Err(msg2)) => {
            println!("Couldn't compile regexs: {}", msg);
            println!("Couldn't open history: {}", msg2);
            exit(1)
        },
        (Err(msg), _) => {
            println!("Couldn't compile regexs: {}", msg);
            exit(1)
        }
        (_, Err(msg)) => {
            println!("Couldn't open history: {}", msg);
            exit(1)
        },
    };
}

fn is_curl_command(line: &str) -> bool {
    line.contains(";curl")
}

fn get_config() -> Config {
    Config::from(App::from_yaml(load_yaml!("cli.yml")).get_matches())
}
