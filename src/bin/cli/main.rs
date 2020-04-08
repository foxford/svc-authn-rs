use std::str::FromStr;

use atty::Stream;
use jsonwebtoken::TokenData;
use serde_json;
use structopt::StructOpt;
use svc_authn::{
    jose::Claims,
    token::jws_compact::{extract, TokenBuilder},
    AccountId,
};

use cli_config::CliConfig;
use extract_expiry::extract_expiry;
use options::{Operation, Opt};

fn main() -> Result<(), String> {
    let opt = Opt::from_args();

    match opt.op {
        Operation::Sign {
            ref expires_in,
            ref expires_at,
            ref cross_audience,
            ref account_id,
            ref config,
        } => {
            let config = CliConfig::from_options(config)?;
            let expires_in = extract_expiry(expires_in, expires_at, &config)?;
            sign(account_id, expires_in, cross_audience, &config)?;
        }
        Operation::Decode { ref token } => {
            decode(token)?;
        }
        Operation::Verify {
            ref token,
            ref config,
        } => {
            let config = CliConfig::from_options(config)?;
            verify(token, &config)?;
        }
    }

    Ok(())
}

fn sign(
    account_id: &str,
    expires_in: i64,
    cross_audience: &Option<String>,
    config: &CliConfig,
) -> Result<(), String> {
    let (account_id, audience) = if let Some(ref cross_aud) = cross_audience {
        let audience = AccountId::from_str(account_id)
            .map_err(|err| format!("Failed to create account id: {}", err))?
            .audience()
            .to_owned();
        let cross_account = format!("{}:{}", account_id, cross_aud);
        let account_id = AccountId::from_str(&cross_account)
            .map_err(|err| format!("Failed to create account id: {}", err))?;
        (account_id, audience)
    } else {
        let account_id = AccountId::from_str(account_id)
            .map_err(|err| format!("Failed to create account id: {}", err))?;
        let audience = account_id.audience().to_owned();
        (account_id, audience)
    };

    let audience_config = &config
        .audience
        .get(&audience)
        .ok_or_else(|| format!("Couldnt find audience: {} in config", account_id))?;

    let token = TokenBuilder::new()
        .issuer(&audience_config.iss)
        .subject(&account_id)
        .key(
            audience_config.algorithm,
            audience_config.sign_key.as_slice(),
        )
        .expires_in(expires_in)
        .build()
        .map_err(|err| format!("Error creating a token: {}", err))?;

    if atty::is(Stream::Stdout) {
        println!("{}", token);
    } else {
        print!("{}", token);
    }

    Ok(())
}

fn verify(token: &str, config: &CliConfig) -> Result<(), String> {
    use chrono::{DateTime, TimeZone, Utc};
    use jsonwebtoken::Validation;

    let nonvalidated_token: TokenData<Claims<String>> = extract::parse_jws_compact(token)
        .map_err(|err| format!("Error decoding token: {}", err))?;
    let claims = nonvalidated_token.claims;
    let claims_audience = claims.audience().splitn(2, ':').collect::<Vec<&str>>()[0];

    let audience_config = &config
        .audience
        .get(claims_audience)
        .ok_or_else(|| format!("Couldnt find audience: {} in config", claims_audience))?;

    let verifier = Validation {
        iss: Some(audience_config.iss.clone()),
        algorithms: vec![audience_config.algorithm],
        ..Validation::default()
    };

    let valid_token: TokenData<Claims<String>> =
        extract::decode_jws_compact(token, &verifier, &audience_config.verify_key)
            .map_err(|err| format!("Failed to decode token: {}", err))?;

    let expires_at = valid_token
        .claims
        .expiration_time()
        .ok_or_else(|| format!("Absent expiration date: {:?}", valid_token.claims))?;
    let expires_at = Utc.timestamp(expires_at as i64, 0);
    let dur = DateTime::signed_duration_since(expires_at, Utc::now());

    if atty::is(Stream::Stdout) {
        println!(
            "Verification passed, token valid for {} seconds",
            dur.num_seconds()
        );
    }

    Ok(())
}

fn decode(token: &str) -> Result<(), String> {
    let t: TokenData<Claims<String>> = extract::parse_jws_compact(token)
        .map_err(|err| format!("Error decoding token: {}", err))?;

    let json = serde_json::to_string(&t.claims)
        .map_err(|err| format!("Failed to format token as json: {}", err))?;
    println!("{}", json);

    Ok(())
}

mod cli_config;
mod extract_expiry;
mod options;
