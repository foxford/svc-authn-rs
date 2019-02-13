use chrono::{Duration, Utc};
use failure::{err_msg, format_err, Error};
use jsonwebtoken::{encode, Algorithm, Header};

use crate::jose::{Claims, ConfigMap};
use crate::Authenticable;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct TokenBuilder<'a> {
    issuer: Option<&'a str>,
    subject: Option<&'a dyn Authenticable>,

    expires_in: Option<i64>,
    algorithm: Option<&'a Algorithm>,
    key: Option<&'a [u8]>,
}

impl<'a> TokenBuilder<'a> {
    pub fn new() -> Self {
        Self {
            issuer: None,
            subject: None,
            expires_in: None,
            algorithm: None,
            key: None,
        }
    }

    pub fn issuer(self, value: &'a str) -> Self {
        Self {
            issuer: Some(value),
            subject: self.subject,
            expires_in: self.expires_in,
            algorithm: self.algorithm,
            key: self.key,
        }
    }

    pub fn subject(self, value: &'a dyn Authenticable) -> Self {
        Self {
            issuer: self.issuer,
            subject: Some(value),
            expires_in: self.expires_in,
            algorithm: self.algorithm,
            key: self.key,
        }
    }

    pub fn expires_in(self, value: i64) -> Self {
        Self {
            issuer: self.issuer,
            subject: self.subject,
            expires_in: Some(value),
            algorithm: self.algorithm,
            key: self.key,
        }
    }

    pub fn key(self, algorithm: &'a Algorithm, key: &'a [u8]) -> Self {
        Self {
            issuer: self.issuer,
            subject: self.subject,
            expires_in: self.expires_in,
            algorithm: Some(algorithm),
            key: Some(key),
        }
    }

    pub fn build(self) -> Result<String, Error> {
        let issuer = self.issuer.ok_or_else(|| err_msg("invalid issuer"))?;
        let subject = self.subject.ok_or_else(|| err_msg("missing subject"))?;
        let algorithm = self.algorithm.ok_or_else(|| err_msg("missing algorithm"))?;
        let key = self.key.ok_or_else(|| err_msg("missing key"))?;

        let claims = Claims::new(
            issuer,
            subject.account_id().audience(),
            subject.account_id().label(),
            self.expires_in
                .map(|val| (Utc::now() + Duration::seconds(val)).timestamp() as u64),
        );

        encode(&Header::new(*algorithm), &claims, key)
            .map_err(|err| format_err!("encoding error – {}", err))
    }
}

////////////////////////////////////////////////////////////////////////////////

pub mod extract {
    use failure::{err_msg, format_err, Error};
    use http::header::HeaderValue;
    use jsonwebtoken::{decode, TokenData, Validation};

    use super::{Claims, ConfigMap};
    use crate::token::bearer::extract::parse_bearer_token;

    pub fn extract_jws_compact<T>(
        header: &HeaderValue,
        authn: &ConfigMap,
    ) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let token = parse_bearer_token(header)?;
        let parts = parse_jws_compact::<T>(token)?;
        let config = authn.get(parts.claims.issuer()).ok_or_else(|| {
            format_err!(
                "issuer = {} of the authentication token is not allowed",
                parts.claims.issuer(),
            )
        })?;

        // NOTE: we consider the token valid if its audience matches at least
        // one audience from the app config for the same issuer.
        // We can't use 'verifier.set_audience(&config.audience)' because it's
        // succeed if only all values from the config represented in the token.
        if !config.audience().contains(parts.claims.audience()) {
            return Err(format_err!(
                "audience = {} of the authentication token is not allowed",
                parts.claims.audience(),
            ));
        }

        let mut verifier = Validation::new(*config.algorithm());
        verifier.validate_exp = parts.claims.expiration_time().is_some();

        decode_jws_compact(token, &verifier, config.key().as_ref())
    }

    pub fn decode_jws_compact<T>(
        token: &str,
        verifier: &Validation,
        key: &[u8],
    ) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        decode(token, key, &verifier).map_err(|err| {
            format_err!(
                "verification of the authentication token failed – {}",
                &err,
            )
        })
    }

    pub fn parse_jws_compact<T>(token: &str) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        jsonwebtoken::dangerous_unsafe_decode(token)
            .map_err(|_| err_msg("invalid claims of the authentication token"))
    }
}
