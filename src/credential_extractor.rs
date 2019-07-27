extern crate regex;

use self::regex::Regex;

pub struct CredentialExtractor {
    auth_header_regex: Regex,
    dash_u_regex: Regex,
}

pub trait AuthorizationExtractor {
    fn get_authorization(&self, arguments: &str) -> Option<(String, String)>;
}

pub trait BasicAuthExtractor {
    fn get_basic_auth(&self, arguments: &str) -> Option<(String, String)>;
}

pub trait CredentialFinder {
    fn has_authorization(&self, arguments: &str) -> bool;
    fn has_basic_auth(&self, arguments: &str) -> bool;
    fn has_credentials(&self, arguments: &str) -> bool;
}

impl CredentialExtractor {

    pub fn new() -> Result<CredentialExtractor, String> {

        let raw_auth_header_regex = "-u [\'\"]([\\w-]*):([\\w-]*)[\'\"]";
        let raw_dash_u_regex = "-H [\'\"]Authorization: ([a-zA-Z]*) ([\\w-]*)[\'\"]";

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
}

impl AuthorizationExtractor for CredentialExtractor {
    fn get_authorization(&self, arguments: &str) -> Option<(String, String)> {
        extract_params(&self.auth_header_regex, arguments)
    }
}

impl BasicAuthExtractor for CredentialExtractor {
    fn get_basic_auth(&self, arguments: &str) -> Option<(String, String)> {
        extract_params(&self.dash_u_regex, arguments)
    }
}

impl CredentialFinder for CredentialExtractor {

    fn has_authorization(&self, arguments: &str) -> bool {
        self.auth_header_regex.is_match(arguments)
    }

    fn has_basic_auth(&self, arguments: &str) -> bool {
        self.dash_u_regex.is_match(arguments)
    }

    fn has_credentials(&self, arguments: &str) -> bool {
        self.auth_header_regex.is_match(arguments) || self.dash_u_regex.is_match(arguments)
    }
}

fn extract_params(regex: &Regex, arguments: &str) -> Option<(String, String)> {
    match regex.captures(arguments) {
        Some(captures) => {
            match (captures.get(1), captures.get(2)) {
                (Some(arg1), Some(arg2)) => Some(((arg1.as_str().to_string()), arg2.as_str().to_string())),
                (_, _) => None,
            }
        },
        None => None,
    }
}
