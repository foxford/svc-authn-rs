use serde::de::{Deserializer, Error, Unexpected, Visitor};
use std::fmt;

////////////////////////////////////////////////////////////////////////////////

struct FileVisitor;

impl<'de> Visitor<'de> for FileVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a path to an existing file")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        use std::fs::File;
        use std::io::Read;

        let mut data = Vec::new();
        File::open(v)
            .and_then(|mut file| file.read_to_end(&mut data).map(|_| data))
            .map_err(|_| Error::invalid_value(Unexpected::Str(v), &self))
    }
}

pub fn file<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(FileVisitor)
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "jose")]
pub use crate::jose::serde::algorithm;
