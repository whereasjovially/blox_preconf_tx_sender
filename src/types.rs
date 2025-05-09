use ethereum_consensus::builder::SignedValidatorRegistration;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Validator {
    #[serde(deserialize_with = "str_to_u64")]
    pub slot: u64,
    #[serde(deserialize_with = "str_to_u64")]
    validator_index: u64,
    entry: SignedValidatorRegistration,
    preferences: BuilderValidatorPreferences
}

// helper to parse a string into a u64
fn str_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuilderValidatorPreferences {
    pub censoring: bool,
    pub filtering: Filtering,
    pub trusted_builders: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Filtering {
    #[default]
    #[serde(rename = "global")]
    Global = 0,
    #[serde(rename = "regional")]
    Regional = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(serialize_with = "serialize_status_code")]
    pub code: u16,
    pub message: String,
}

pub fn serialize_status_code<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}