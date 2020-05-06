use std::collections::HashMap;
use std::path::PathBuf;

use serde_derive::Deserialize;

const DEFAULT_CONFIG_FILE: &str = ".svc/authn/Cli.toml";
const DEFAULT_CONFIG: &str = r#"
expires_in = 86400 # one day

[audience."example.com"]
iss = "bar.services"
algorithm = "HS256"
sign_key = "/path/to/keys/bar.private_key.p8.der.sample"
verify_key = "/path/to/keys/bar.public_key.p8.der.sample"
"#;

#[derive(Deserialize, Debug)]
pub(crate) struct CliConfig {
    pub audience: HashMap<String, AudienceConfig>,
    pub expires_in: Option<i64>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct AudienceConfig {
    #[serde(deserialize_with = "svc_authn::serde::algorithm")]
    pub algorithm: svc_authn::jose::Algorithm,
    #[serde(deserialize_with = "svc_authn::serde::file")]
    pub sign_key: Vec<u8>,
    #[serde(deserialize_with = "svc_authn::serde::file")]
    pub verify_key: Vec<u8>,
    pub iss: String,
}

impl CliConfig {
    #[cfg(test)]
    pub fn new(expires_in: Option<i64>) -> Self {
        Self {
            audience: HashMap::new(),
            expires_in,
        }
    }

    pub fn from_options(path: &Option<PathBuf>) -> Result<Self, String> {
        let path = match &path {
            Some(path) => path.clone(),
            None => {
                let mut path =
                    dirs::home_dir().ok_or_else(|| "Failed to get home dir".to_string())?;
                path.push(DEFAULT_CONFIG_FILE);
                if !path.exists() {
                    std::fs::write(&path, DEFAULT_CONFIG).map_err(|err| {
                        format!(
                            "Tried to create default config at {}\nBut something went wrong: {}",
                            DEFAULT_CONFIG_FILE, err
                        )
                    })?;

                    return Err(format!(
                        "Created a config for you at {}\nBut you must add some audiences, exiting.",
                        DEFAULT_CONFIG_FILE
                    ));
                }
                path
            }
        };

        let mut settings = config::Config::default();
        settings
            .merge(config::File::from(path))
            .map_err(|err| format!("Failed to read config: {}", err))?;
        settings
            .try_into()
            .map_err(|err| format!("Failed to deserialize config: {}", err))
    }
}
