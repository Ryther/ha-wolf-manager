use crate::SafeError;
use serde::{Deserialize, Deserializer, Serialize};
macro_rules! identifier {
    ($name:ident,$validate:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, SafeError> {
                let value = value.into();
                if ($validate)(&value) {
                    Ok(Self(value))
                } else {
                    Err(SafeError::validation())
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }
    };
}
identifier!(PcId, |s: &str| !s.is_empty()
    && s.len() <= 64
    && (s.as_bytes()[0].is_ascii_lowercase()
        || s.as_bytes()[0].is_ascii_digit())
    && s.bytes().all(|b| b.is_ascii_lowercase()
        || b.is_ascii_digit()
        || b == b'_'
        || b == b'-'));
identifier!(AppId, |s: &str| !s.is_empty()
    && s.len() <= 12
    && s.bytes().all(|b| b.is_ascii_digit()));
identifier!(ParameterId, |s: &str| !s.is_empty()
    && s.len() <= 64
    && s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)));
identifier!(Revision, |s: &str| s.len() == 64
    && s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
