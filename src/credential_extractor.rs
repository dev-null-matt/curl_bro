use clap::App;
use clap::ArgMatches;
use yaml_rust::yaml::Yaml;

pub struct CredentialExtractor<'a> {
    app: App<'a, 'a>,
}

pub trait AuthorizationExtractor {
    fn get_authorization(&self, arguments: &str) -> Option<(String, String)>;
}

pub trait BasicAuthExtractor {
    fn get_basic_auth(&self, arguments: &str) -> Option<(String, String)>;
}

impl<'a> CredentialExtractor<'a> {

    pub fn new(yaml: &'a Yaml) -> CredentialExtractor<'a> {
        CredentialExtractor {
            app: App::from_yaml(yaml)
        }
    }
}

impl<'a> AuthorizationExtractor for CredentialExtractor<'a> {
    fn get_authorization(&self, arguments: &str) -> Option<(String, String)> {
        match extract_params(&self.app, "header", arguments) {
            Some(headers) => {
                match headers.iter().find(|header| header.starts_with("Authorization: ")) {
                    Some(header) => decompose_auth_header(header),
                    None => None,
                }
            },
            None => None,
        }
    }
}

impl<'a> BasicAuthExtractor for CredentialExtractor<'a> {
    fn get_basic_auth(&self, arguments: &str) -> Option<(String, String)> {
        match extract_param(&self.app, "user", arguments) {
            Some(credentials) => {
                let parts = credentials.split(":").collect::<Vec<&str>>();
                match (parts.get(0), parts.get(1)) {
                    (Some(username), Some(password)) => Some((username.to_string(), password.to_string())),
                    (_, _) => None,
                }
            },
            None => None,
        }
    }
}

fn extract_param(app: &App, arg_name: &str, arguments: &str) -> Option<String> {
    match app.clone().get_matches_from_safe(tokenize_command_string(arguments)) {
        Ok(arg_result) => {
            match arg_result.value_of(arg_name) {
                Some(value) => Some(value.to_string()),
                _ => None,
            }
        },
        Err(_) => None,
    }
}

fn extract_params(app: &App, arg_name: &str, arguments: &str) -> Option<Vec<String>> {
    match app.clone().get_matches_from_safe(tokenize_command_string(arguments)) {
        Ok(arg_result) => {
            match arg_result.values_of(arg_name) {
                Some(values) => Some(values.map(|s| s.to_string()).collect()),
                _ => None,
            }
        },
        Err(_) => None,
    }
}

fn decompose_auth_header(header: &str) -> Option<(String, String)>{
    let (_, authorization) = header.split_at(15);
    let parts = authorization.split(" ").collect::<Vec<&str>>();
    match (parts.get(0), parts.get(1)) {
        (Some(auth_type), Some(credentials)) => Some((auth_type.to_string(), credentials.to_string())),
        (_, _) => None
    }
}

fn tokenize_command_string(arguments: &str) -> Vec<String> {

    let mut tokens:Vec<String> = Vec::new();
    let mut buffer: String = "".to_string();
    let mut escaped: bool = false;
    let mut  quote_char: Option<char> = None;

    arguments.chars().for_each(|char| {

        match (char,  quote_char) {

            // Backlash escapes characters
            ('\\', _) => escaped = true,

            // Starts a quoted string
            ('\'', None) if !escaped =>  quote_char = Some('\''),
            ('"', None) if !escaped =>  quote_char = Some('"'),

            // Closes a quoted string; saves the buffer to the token list
            ('\'', Some(ref char)) if !escaped && char == &'\'' => {
                quote_char = None;
                tokens.push(buffer.to_string());
                buffer = "".to_string()
            },
            ('"', Some(ref char)) if !escaped && char == &'"' => {
                quote_char = None;
                tokens.push(buffer.to_string());
                buffer = "".to_string()
            },

            // Space in an unquoted string; saves the buffer to the token list
            (' ', None) => {
                if (buffer.len() > 0) {
                    tokens.push(buffer.to_string());
                    buffer = "".to_string()
                }
            },

            // Append the current char to the buffer
            (_, _) => {
                escaped = false;
                buffer = format!("{}{}", buffer, char)
            },
        }
    });

    tokens
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn extract_basic_auth() {

        let curl_yaml = load_yaml!("curl.yml");
        let extractor = CredentialExtractor::new(curl_yaml);

        match extractor.get_basic_auth(r#"curl https://auth-globald.smartthingsgdev.com/oauth/check_token -F "token=token" -u "user-name:password""#) {
            Some((username, password)) => {
                assert_eq!(username, "user-name");
                assert_eq!(password, "password");
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn tokenize_command_string_mixed_quotes() {

        let tokens = tokenize_command_string(r#"curl localhost:8080/foo/bar -F "foo=bar" -H 'Authorization: Bearer token'"#);

        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens.get(0).unwrap(), "curl");
        assert_eq!(tokens.get(1).unwrap(), "localhost:8080/foo/bar");
        assert_eq!(tokens.get(2).unwrap(), "-F");
        assert_eq!(tokens.get(3).unwrap(), "foo=bar");
        assert_eq!(tokens.get(4).unwrap(), "-H");
        assert_eq!(tokens.get(5).unwrap(), "Authorization: Bearer token");
    }

    #[test]
    fn tokenize_command_string_escaped_quotes() {

        let tokens = tokenize_command_string(r#"curl localhost:8080/foo/bar -F "foo=b\"ar" -H 'Authorization: Bearer token'"#);

        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens.get(0).unwrap(), "curl");
        assert_eq!(tokens.get(1).unwrap(), "localhost:8080/foo/bar");
        assert_eq!(tokens.get(2).unwrap(), "-F");
        assert_eq!(tokens.get(3).unwrap(), "foo=b\"ar");
        assert_eq!(tokens.get(4).unwrap(), "-H");
        assert_eq!(tokens.get(5).unwrap(), "Authorization: Bearer token");
    }

    #[test]
    fn tokenize_command_string_data_param() {

        let tokens = tokenize_command_string(r#"curl -H 'Authorization: Bearer token' -X POST 'https://auth-globald.smartthingsgdev.com/clients' -d '{"id":"id","accessTokenValiditySeconds":1577846300,"additionalInformation":{},"authorizedGrantTypes":["client_credentials"],"name":"Create client script client","registeredRedirectUri":null,"scope":["service"],"clientSecret":"lol_nope"}'"#);

        assert_eq!(tokens.len(), 8);
        assert_eq!(tokens.get(0).unwrap(), "curl");
        assert_eq!(tokens.get(1).unwrap(), "-H");
        assert_eq!(tokens.get(2).unwrap(), "Authorization: Bearer token");
        assert_eq!(tokens.get(3).unwrap(), "-X");
        assert_eq!(tokens.get(4).unwrap(), "POST");
        assert_eq!(tokens.get(5).unwrap(), "https://auth-globald.smartthingsgdev.com/clients");
        assert_eq!(tokens.get(6).unwrap(), "-d");
        assert_eq!(tokens.get(7).unwrap(), r#"{"id":"id","accessTokenValiditySeconds":1577846300,"additionalInformation":{},"authorizedGrantTypes":["client_credentials"],"name":"Create client script client","registeredRedirectUri":null,"scope":["service"],"clientSecret":"lol_nope"}"#);

    }
}
