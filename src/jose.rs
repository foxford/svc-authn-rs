use jsonwebtoken::Algorithm;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type ConfigMap = HashMap<String, Config>;

#[derive(Debug, Deserialize)]
pub struct Config {
    audience: HashSet<String>,
    #[serde(deserialize_with = "crate::serde::algorithm")]
    algorithm: Algorithm,
    #[serde(deserialize_with = "crate::serde::file")]
    key: Vec<u8>,
}

impl Config {
    pub fn audience(&self) -> &HashSet<String> {
        &self.audience
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.key
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<T> {
    iss: String,
    aud: String,
    sub: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
}

impl<T> Claims<T> {
    pub fn issuer(&self) -> &str {
        &self.iss
    }

    pub fn audience(&self) -> &str {
        &self.aud
    }

    pub fn subject(&self) -> &T {
        &self.sub
    }

    pub fn expiration_time(&self) -> Option<u64> {
        self.exp
    }

    pub fn new(iss: &str, aud: &str, sub: T, exp: Option<u64>) -> Self {
        Self {
            iss: iss.to_owned(),
            aud: aud.to_owned(),
            sub,
            exp,
        }
    }
}
