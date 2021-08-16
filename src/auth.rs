use crate::types::request::{self, Authentication, Credential, CredentialValue, Password, Username};

#[derive(Debug)]
pub enum CredentialType {
    UsernameAndPassword(UsernameAndPasswordCredential),
}

#[derive(Debug)]
pub struct UsernameAndPasswordCredential {
    pub username: String,
    pub password: Option<String>,
}

impl UsernameAndPasswordCredential {
    pub fn new(username: String, password: Option<String>) -> Self {
        Self { username, password }
    }
}

impl Authentication {
    pub fn build(credential: CredentialType) -> Authentication {
        match credential {
            CredentialType::UsernameAndPassword(inner) => {
                let username = Username(inner.username);
                let password = inner.password.map(Password);
                Authentication(Credential(
                    request::CredentialType::UsernameAndPassword,
                    CredentialValue::UsernameAndPassword(username, password),
                ))
            }
        }
    }
}
