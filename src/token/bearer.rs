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
    use failure::{err_msg, Error};
    use http::header::HeaderValue;

    pub fn parse_bearer_token(header: &HeaderValue) -> Result<&str, Error> {
        let val: Vec<&str> = header
            .to_str()
            .map_err(|_| err_msg("invalid characters in the authorization header"))?
            .split(' ')
            .collect();

        match val[..] {
            ["Bearer", ref val] => Ok(val),
            _ => Err(err_msg(
                "unsupported or invalid type of the authentication token",
            )),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "tower-web")]
pub mod tower_web {
    use super::{extract::parse_bearer_token, Token};

    pub mod extract {
        use http::StatusCode;
        use tower_web::extract::{Context, Error, Extract, Immediate};
        use tower_web::util::BufStream;

        use super::{parse_bearer_token, Token};

        impl<B: BufStream> Extract<B> for Token {
            type Future = Immediate<Token>;

            fn extract(context: &Context) -> Self::Future {
                match context.request().headers().get(http::header::AUTHORIZATION) {
                    Some(header) => match parse_bearer_token(&header) {
                        Ok(token) => Immediate::ok(Token::new(token)),
                        Err(ref err) => {
                            Immediate::err(error(&err.to_string(), StatusCode::UNAUTHORIZED))
                        }
                    },
                    None => {
                        Immediate::err(error("missing authentication token", StatusCode::FORBIDDEN))
                    }
                }
            }
        }

        fn error(detail: &str, status: StatusCode) -> Error {
            let mut err = tower_web::Error::new(
                "authn_error",
                "Error processing the authentication token",
                status,
            );
            err.set_detail(detail);
            err.into()
        }
    }
}
