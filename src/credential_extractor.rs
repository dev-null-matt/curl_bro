extern crate regex;

use self::regex::Regex;

pub struct CredentialExtractor {
    auth_header_regex: Regex,
    dash_u_regex: Regex,
}

pub trait HasCredentials {
    fn has_credentials(&self, arguments: &str) -> bool;
}

impl CredentialExtractor {

    pub fn new() -> Result<CredentialExtractor, String> {

        let raw_auth_header_regex = "-u [\'\"](.*):(.*)[\'\"]";
        let raw_dash_u_regex = "-H [\'\"]Authorization: ([a-zA-Z]*) (.*)[\'\"]";

        match (
            Regex::new(raw_auth_header_regex),
            Regex::new(raw_dash_u_regex),
        ) {
            (Ok(auth_header_regex), Ok(dash_u_regex)) => {
                Ok(CredentialExtractor {
                    auth_header_regex: auth_header_regex,
                    dash_u_regex: dash_u_regex,
                })
            },
            _ => Err("Unable to parse regular expressions".to_string()),
        }
    }

    pub fn has_credentials(&self, arguments: &str) -> bool {
        self.auth_header_regex.is_match(arguments) || self.dash_u_regex.is_match(arguments)
    }
}
