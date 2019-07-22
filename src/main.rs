#[macro_use]
extern crate clap;

mod config;

use config::Config;

use clap::App;

fn main() {

    let config = get_config();

    println!("History count was {}", config.history_count);
}

fn get_config() -> Config {
    Config::from(App::from_yaml(load_yaml!("cli.yml")).get_matches())
}
