#[cfg_attr(feature = "diesel", macro_use)]
#[cfg(feature = "diesel")]
extern crate diesel;

use std::fmt;

pub trait Authenticable: Sync + Send {
    fn as_account_id(&self) -> &AccountId;
}

impl fmt::Debug for &dyn Authenticable {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Authenticable").finish()
    }
}

#[cfg(feature = "jose")]
pub mod jose;

pub use self::account::AccountId;
#[cfg(feature = "diesel")]
pub mod sql {
    pub use super::account::sql::Account_id;
}
mod account;

pub mod token;

#[cfg(feature = "jose")]
pub(crate) mod serde;
