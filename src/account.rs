use std::fmt;
use std::str::FromStr;

use crate::Authenticable;
use crate::Error;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "diesel", derive(FromSqlRow, AsExpression))]
#[cfg_attr(feature = "diesel", diesel(sql_type = sql::Account_id))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "account_id"))]
pub struct AccountId {
    label: String,
    audience: String,
}

impl AccountId {
    pub fn new(label: &str, audience: &str) -> Self {
        Self {
            label: label.to_owned(),
            audience: audience.to_owned(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}.{}", self.label, self.audience)
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = val.splitn(2, '.').collect();
        match parts[..] {
            [label, audience] => Ok(Self::new(label, audience)),
            _ => Err(Error::new(&format!(
                "invalid value for the application name: {}",
                val
            ))),
        }
    }
}

impl Authenticable for AccountId {
    fn as_account_id(&self) -> &Self {
        self
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "jose")]
pub mod jose {
    use super::AccountId;
    use crate::jose::Claims;

    impl From<Claims<String>> for AccountId {
        fn from(value: Claims<String>) -> Self {
            Self::new(value.subject(), value.audience())
        }
    }
}

#[cfg(feature = "diesel")]
pub mod sql {
    use diesel::backend::Backend;
    use diesel::deserialize::{self, FromSql};
    use diesel::pg::Pg;
    use diesel::serialize::{self, Output, ToSql, WriteTuple};
    use diesel::sql_types::{Record, Text};

    use super::AccountId;

    #[derive(SqlType, QueryId)]
    #[diesel(postgres_type(name = "account_id"))]
    #[allow(non_camel_case_types)]
    pub struct Account_id;

    impl ToSql<Account_id, Pg> for AccountId {
        fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
            WriteTuple::<(Text, Text)>::write_tuple(&(&self.label, &self.audience), out)
        }
    }

    impl FromSql<Account_id, Pg> for AccountId {
        fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
            let (label, audience): (String, String) =
                FromSql::<Record<(Text, Text)>, Pg>::from_sql(bytes)?;
            Ok(AccountId::new(&label, &audience))
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

mod serde {
    use serde::{de, ser};
    use std::fmt;

    use super::AccountId;

    impl ser::Serialize for AccountId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> de::Deserialize<'de> for AccountId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct AccountIdVisitor;

            impl<'de> de::Visitor<'de> for AccountIdVisitor {
                type Value = AccountId;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("struct AccountId")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    use std::str::FromStr;

                    AccountId::from_str(v)
                        .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(v), &self))
                }
            }

            deserializer.deserialize_str(AccountIdVisitor)
        }
    }
}
