use std::ops::Deref;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Token {
    inner: String,
}

impl Token {
    pub fn new(inner: &str) -> Self {
        Self {
            inner: inner.to_owned(),
        }
    }
}

impl Deref for Token {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

////////////////////////////////////////////////////////////////////////////////

pub mod extract {
    use http::header::HeaderValue;

    use crate::Error;

    pub fn parse_bearer_token(header: &HeaderValue) -> Result<&str, Error> {
        let val: Vec<&str> = header
            .to_str()
            .map_err(|_| Error::new("invalid characters in the authorization header"))?
            .split(' ')
            .collect();

        match val[..] {
            ["Bearer", val] => Ok(val),
            _ => Err(Error::new(
                "unsupported or invalid type of the authentication token",
            )),
        }
    }
}
