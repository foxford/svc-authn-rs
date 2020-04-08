use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub(crate) enum Operation {
    /// Creates new token
    Sign {
        #[structopt(short, long, parse(from_os_str))]
        /// Authn config to use, defaults to ~/.svc/authn-cli.toml
        config: Option<PathBuf>,
        #[structopt(short, long)]
        /// Account id to issue/verify token for, required
        account_id: String,
        /// Number of seconds before token expires
        #[structopt(long, group = "expires")]
        expires_in: Option<i64>,
        /// DateTime when token should expire, acceptable formats are YYYY-MM-DD and YYYY-MM-DD hh:mm:ss
        #[structopt(long, group = "expires")]
        expires_at: Option<String>,
        #[structopt(long)]
        cross_audience: Option<String>,
    },
    /// Verifies token is valid and up to date
    Verify {
        #[structopt(short, long, parse(from_os_str))]
        /// Authn config to use, defaults to ~/.svc/authn-cli.toml
        config: Option<PathBuf>,
        /// Token to verify
        token: String,
    },
    /// Prints token contents
    Decode {
        /// Token to decode
        token: String,
    },
}

#[derive(StructOpt, Debug)]
#[structopt(name = "svc-authn-cli")]
pub(crate) struct Opt {
    #[structopt(subcommand)]
    pub(crate) op: Operation,
}
