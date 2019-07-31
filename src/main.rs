#[macro_use]
extern crate clap;
extern crate yaml_rust;

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

    let curl_yaml = load_yaml!("curl.yml");
    let extractor = CredentialExtractor::new(curl_yaml);

    //let history_file = "/Users/matthewrick/Documents/src/curl_bro/test.history";
    let history_file = format!("/Users/matthewrick/.{}_history", shell);

    match File::open(history_file) {
        Ok(history) => for result in BufReader::new(history).lines() {
            match result {
                Err(e) => println!("Error reading line: {}", e),
                Ok(ref line) => {
                    match get_curl_command(line) {
                        Some(ref command) => {
                            match (
                                extractor.get_authorization(command),
                                extractor.get_basic_auth(command),
                            ) {
                                (Some((auth_type, authentication)), _) => println!("Authorization: {} {}", auth_type, authentication),
                                (_, Some((username, password))) => println!("{}:{}", username, password),
                                (_, _) => ()
                            }
                        },
                        None => (),
                    }
                }
            }
        },
        Err(msg) => {
            println!("Couldn't open history: {}", msg);
            exit(1)
        },
    };
}

fn get_curl_command(line: &str) -> Option<String> {
    let parts = line.split(";curl").collect::<Vec<&str>>();
    match (parts.get(0), parts.get(1)) {
        (_, Some(command_args)) => Some(format!("curl{}", command_args)),
        (_, _) => None,
    }
}

fn get_config() -> Config {
    Config::from(App::from_yaml(load_yaml!("curl_bro.yml")).get_matches())
}
