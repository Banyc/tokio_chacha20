use std::{hash::Hash, sync::Arc};

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::KEY_BYTES;

pub type ConfigKey = Arc<[u8]>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct ConfigBuilder(pub String);
impl ConfigBuilder {
    pub fn build(&self) -> Result<Config, ConfigBuildError> {
        let key = BASE64_STANDARD_NO_PAD
            .decode(&self.0)
            .map_err(|e| ConfigBuildError {
                source: e,
                key: self.0.clone(),
            })?;
        Ok(Config::new(key.into()))
    }
}
#[derive(Debug, Error)]
#[error("{source}, key = `{key}`")]
pub struct ConfigBuildError {
    #[source]
    pub source: base64::DecodeError,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Config {
    key: [u8; KEY_BYTES],
}
impl Config {
    pub fn new(key: ConfigKey) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&key);
        let key = hasher.finalize();
        let key = *key.as_bytes();
        Self { key }
    }

    pub fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn create_random_config() -> Config {
        let key: [u8; KEY_BYTES] = rand::random();
        Config::new(key.into())
    }

    #[test]
    fn test_config() {
        let _key = create_random_config();
    }
}
