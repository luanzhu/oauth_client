#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate roadrunner;
extern crate hyper;

use std::convert::From;

use hyper::StatusCode;
use tokio_core::reactor::Core;
use roadrunner::{RestClient, RestClientMethods};

#[derive(Debug)]
pub enum Error {
    FieldNotSuppliedError(&'static str),
    NoneOkStatusCodeError(u16),
    RestClientError(roadrunner::Error),
}

impl From<roadrunner::Error> for Error {
    fn from(err: roadrunner::Error) -> Self {
        Error::RestClientError(err)
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Token {
    access_token: String,
    token_type: String,
    expires_in: u32,
    scope: String,
}

impl Token {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }
}

#[derive(Debug, PartialEq)]
pub enum GrantType {
    ClientCredentials,
}

impl GrantType {
    fn to_str(&self) -> &'static str {
        match *self {
            GrantType::ClientCredentials => "client_credentials",
        }
    }
}

pub struct OAuthClient<'a> {
    grant_type: Option<GrantType>,
    scope: Option<&'a str>,
    token_url: Option<&'a str>,

    client_id: Option<&'a str>,
    client_password: Option<&'a str>,
}

macro_rules! check_field_and_return_error {
    ($f:expr, $s:expr) => {
        match $f {
            Some(v) => v,
            None => { return Err(Error::FieldNotSuppliedError($s)); }
        }
    };
}

impl<'a> OAuthClient<'a> {
    pub fn new() -> OAuthClient<'a> {
        OAuthClient {
            grant_type: None,
            scope: None,
            token_url: None,

            client_id: None,
            client_password: None,
        }
    }

    pub fn grant_type(mut self, grant_type: GrantType) -> Self {
        self.grant_type = Some(grant_type);

        self
    }

    pub fn scope(mut self, scope: &'a str) -> Self {
        self.scope = Some(scope);

        self
    }

    pub fn token_url(mut self, token_url: &'a str) -> Self {
        self.token_url = Some(token_url);

        self
    }

    pub fn client_id(mut self, client_id: &'a str) -> Self {
        self.client_id = Some(client_id);

        self
    }

    pub fn client_password(mut self, client_password: &'a str) -> Self {
        self.client_password = Some(client_password);

        self
    }

    pub fn execute_on(&self, core: &mut Core) -> Result<Token, Error> {
        match self.grant_type {
            Some(ref grant_type) => {
               match grant_type {
                   &GrantType::ClientCredentials => {
                       let scope_value = check_field_and_return_error!(self.scope, "scope");
                       let token_url_value = check_field_and_return_error!(self.token_url, "token_url");
                       let client_id_value = check_field_and_return_error!(self.client_id, "client_id");
                       let client_password_value = check_field_and_return_error!(self.client_password, "client_password");

                       RestClient::post(token_url_value)
                            .authorization_basic(client_id_value.to_owned(), client_password_value.to_owned())
                            .form_field("scope", scope_value)
                            .form_field("grant_type", grant_type.to_str())
                            .execute_on(core)
                            .map_err(|e| Error::RestClientError(e))
                            .and_then(|response| {
                                if *response.status() == hyper::StatusCode::Ok {
                                    response.content()
                                        .as_typed::<Token>()
                                        .map_err(|e| Error::RestClientError(e))
                                } else {
                                    Err(Error::NoneOkStatusCodeError(u16::from(*response.status())))
                                }
                            })
                   },
               }
            },
            None => { Err(Error::FieldNotSuppliedError("grant_type")) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! check_for_field_not_supplied_error {
        ($r:expr, $n:expr) => {
            match $r {
                Ok(_) => { panic!("Expected Err, but got Ok."); },
                Err(e) => {
                    match e {
                        Error::FieldNotSuppliedError(str) => { assert_eq!(str, $n); },
                        Error::NoneOkStatusCodeError(_) => { panic!("Expected FieldNotSuppliedError only")},
                        Error::RestClientError(_) => { panic!("Expected FieldNotSuppliedError only")},
                    }
                }
            }
        };
    }

    #[test]
    fn grant_type_assign_test() {
        assert_eq!(None, OAuthClient::new().grant_type);
        assert_eq!(Some(GrantType::ClientCredentials), OAuthClient::new()
            .grant_type(GrantType::ClientCredentials)
            .grant_type);
    }

    #[test]
    fn scope_assign_test() {
        assert_eq!(None, OAuthClient::new().scope);

        let hello = "Hello world!";
        assert_eq!(Some(hello), OAuthClient::new()
            .scope(hello)
            .scope);

        let hello_owned = hello.to_owned();
        assert_eq!(Some(hello), OAuthClient::new()
            .scope(&hello_owned)
            .scope);
    }

    #[test]
    fn token_url_assign_test() {
        assert_eq!(None, OAuthClient::new().token_url);

        let url = "https://github.com/luanzhu/roadrunner/blob/master/src/lib.rs";
        assert_eq!(Some(url), OAuthClient::new()
            .token_url(url)
            .token_url);
    }

    #[test]
    fn client_id_assign_test() {
        assert_eq!(None, OAuthClient::new().client_id);

        let client_id = "fake::fake-scope";
        assert_eq!(Some(client_id), OAuthClient::new()
            .client_id(client_id)
            .client_id);
    }

    #[test]
    fn client_password_assign_test() {
        assert_eq!(None, OAuthClient::new().client_password);

        let client_passwrod = "45okjbsdf-asf";
        assert_eq!(Some(client_passwrod), OAuthClient::new()
            .client_password(client_passwrod)
            .client_password);
    }

    #[test]
    fn execute_on_grant_type_not_set_test() {
        let mut core = Core::new().unwrap();

        check_for_field_not_supplied_error!(OAuthClient::new()
            .execute_on(&mut core), "grant_type");
    }

    #[test]
    fn execute_on_scope_not_set_test() {
        let mut core = Core::new().unwrap();

        check_for_field_not_supplied_error!(OAuthClient::new()
            .grant_type(GrantType::ClientCredentials)
            .execute_on(&mut core), "scope");
    }

    #[test]
    fn execute_on_token_url_not_set_test() {
        let mut core = Core::new().unwrap();

        check_for_field_not_supplied_error!(OAuthClient::new()
            .grant_type(GrantType::ClientCredentials)
            .scope("fake::scope")
            .execute_on(&mut core), "token_url");
    }

    #[test]
    fn execute_on_client_id_not_set_test() {
        let mut core = Core::new().unwrap();

        check_for_field_not_supplied_error!(OAuthClient::new()
            .grant_type(GrantType::ClientCredentials)
            .scope("fake::scope")
            .token_url("https://token.url.com")
            .execute_on(&mut core), "client_id");
    }

    #[test]
    fn execute_on_client_password_not_set_test() {
        let mut core = Core::new().unwrap();

        check_for_field_not_supplied_error!(OAuthClient::new()
            .grant_type(GrantType::ClientCredentials)
            .scope("fake::scope")
            .token_url("https://token.url.com")
            .client_id("client-id-string")
            .execute_on(&mut core), "client_password");
    }
}
