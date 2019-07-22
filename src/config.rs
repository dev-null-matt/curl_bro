use clap::ArgMatches;

#[derive(Clone)]
pub struct Config {

    pub history_count: u16
}

impl<'a> From<ArgMatches<'a>> for Config {
    fn from(matches: ArgMatches) -> Config {
        Config {
            history_count: matches
                .value_of("history_count")
                .expect("History count has a default value")
                .parse::<u16>()
                .expect("History count must be a positive number")
        }
    }
}
