//! Local and provider metadata; the benchmark preset selects a remote provider. Measurement is independent.
pub mod remote;
use crate::{Error, Result, discovery::read_bounded};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub location: Option<String>,
}
pub type Database = BTreeMap<IpAddr, Metadata>;
pub(crate) fn validate(entry: &Metadata) -> Result<()> {
    if entry.asn == Some(0) {
        return Err(Error::Config("ASN must be nonzero or null".into()));
    }
    for value in [&entry.organization, &entry.location].into_iter().flatten() {
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(Error::Config("invalid enrichment text".into()));
        }
    }
    Ok(())
}
pub fn load(path: &Path) -> Result<Database> {
    let data: Database = serde_json::from_slice(&read_bounded(path, 2 * 1024 * 1024)?)?;
    if data.len() > 16384 {
        return Err(Error::Config(
            "enrichment database exceeds 16384 addresses".into(),
        ));
    }
    for entry in data.values() {
        validate(entry)?;
    }
    Ok(data)
}
