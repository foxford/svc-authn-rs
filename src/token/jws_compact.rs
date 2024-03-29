use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

use crate::jose::{Claims, ConfigMap};
use crate::SerializationError;
use crate::{AccountId, Authenticable};

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Default)]
pub struct TokenBuilder<'a> {
    issuer: Option<&'a str>,
    subject: Option<&'a AccountId>,

    expires_in: Option<i64>,
    algorithm: Option<Algorithm>,
    key: Option<&'a [u8]>,
}

impl<'a> TokenBuilder<'a> {
    pub fn new() -> Self {
        Default::default()
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

    pub fn subject<A>(self, value: &'a A) -> Self
    where
        A: Authenticable,
    {
        Self {
            issuer: self.issuer,
            subject: Some(value.as_account_id()),
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

    pub fn key(self, algorithm: Algorithm, key: &'a [u8]) -> Self {
        Self {
            issuer: self.issuer,
            subject: self.subject,
            expires_in: self.expires_in,
            algorithm: Some(algorithm),
            key: Some(key),
        }
    }

    pub fn build(self) -> Result<String, SerializationError> {
        let issuer = self
            .issuer
            .ok_or_else(|| SerializationError::new("invalid issuer"))?;
        let subject = self
            .subject
            .ok_or_else(|| SerializationError::new("missing subject"))?;
        let algorithm = self
            .algorithm
            .ok_or_else(|| SerializationError::new("missing algorithm"))?;
        let key = self
            .key
            .ok_or_else(|| SerializationError::new("missing key"))?;

        let mut claims = Claims::new(
            issuer,
            subject.as_account_id().audience(),
            subject.as_account_id().label(),
        );

        if let Some(value) = self.expires_in {
            claims.set_expiration_time((Utc::now() + Duration::seconds(value)).timestamp() as u64);
        }

        let encoding_key = match algorithm {
            Algorithm::HS256 => Ok(EncodingKey::from_secret(key)),
            Algorithm::ES256 => Ok(EncodingKey::from_ec_der(key)),
            _ => Err(SerializationError::new(&format!(
                "unsupported algorithm {:?}",
                algorithm,
            ))),
        }?;

        encode(&Header::new(algorithm), &claims, &encoding_key)
            .map_err(|e| SerializationError::new(&format!("encoding error, {}", e)))
    }
}

////////////////////////////////////////////////////////////////////////////////

pub mod extract {
    use http::header::HeaderValue;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};

    use super::{Claims, ConfigMap};
    use crate::token::bearer::extract::parse_bearer_token;
    use crate::Error;

    pub fn extract_jws_compact<T>(
        header: &HeaderValue,
        authn: &ConfigMap,
    ) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        parse_bearer_token(header)
            .and_then(|token| decode_jws_compact_with_config::<T>(token, authn))
    }

    pub fn decode_jws_compact_with_config<T>(
        token: &str,
        authn: &ConfigMap,
    ) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let parts = parse_jws_compact::<T>(token)?;
        let config = authn.get(parts.claims.issuer()).ok_or_else(|| {
            Error::new(&format!(
                "issuer = {} of the authentication token is not allowed",
                parts.claims.issuer(),
            ))
        })?;

        // NOTE: we consider the token valid if its audience matches at least
        // one audience from the app config for the same issuer.
        // We can't use 'verifier.set_audience(&config.audience)' because it's
        // succeed if only all values from the config represented in the token.
        //
        // If audience is in format '{audience1}:{audience2}' we check first audience
        // Split will always return at least one part
        let audience = parts.claims.audience().split(':').next().unwrap();
        if !config.audience().contains(audience) {
            return Err(Error::new(&format!(
                "audience = {} of the authentication token is not allowed",
                parts.claims.audience(),
            )));
        }

        let mut verifier = Validation::new(config.algorithm());
        verifier.validate_exp = parts.claims.expiration_time().is_some();

        decode_jws_compact(token, &verifier, config.key().as_ref(), config.algorithm())
    }

    pub fn decode_jws_compact<T>(
        token: &str,
        verifier: &Validation,
        key: &[u8],
        algorithm: Algorithm,
    ) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let decoding_key = match algorithm {
            Algorithm::HS256 => Ok(DecodingKey::from_secret(key)),
            Algorithm::ES256 => Ok(DecodingKey::from_ec_der(key)),
            _ => Err(Error::new(&format!(
                "unsupported algorithm {:?}",
                algorithm
            ))),
        }?;

        decode(token, &decoding_key, verifier).map_err(|err| {
            Error::new(&format!(
                "verification of the authentication token failed – {}",
                &err,
            ))
        })
    }

    pub fn parse_jws_compact<T>(token: &str) -> Result<TokenData<Claims<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        jsonwebtoken::dangerous_insecure_decode(token)
            .map_err(|_| Error::new("invalid claims of the authentication token"))
    }
}
