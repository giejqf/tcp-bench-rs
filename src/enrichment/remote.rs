//! Remote adapters do not participate in packet measurement. Nothing here contacts
//! a provider until a configured enrichment pass is requested (including the benchmark preset).
use super::{Database, Metadata, validate};
use crate::{
    Error, Result,
    discovery::{read_bounded, write_cache},
    http::{Client, Endpoint},
    scheduler::{Cancellation, RateLimiter},
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_RESPONSE: usize = 16 * 1024;
const MAX_CACHE: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    RipeStat,
    IpinfoLite,
    Json,
}
impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Self::RipeStat => "ripe_stat",
            Self::IpinfoLite => "ipinfo_lite",
            Self::Json => "json",
        }
    }
    fn attribution(self) -> Option<String> {
        match self {
            Self::RipeStat => {
                Some("RIPEstat / RIPE NCC and RIPE RIS — https://stat.ripe.net".into())
            }
            Self::IpinfoLite => Some("IPinfo — https://ipinfo.io".into()),
            Self::Json => None,
        }
    }
}
// Deliberately no Debug/Serialize: authentication must not appear in reports/logs/cache.
pub struct Config {
    pub provider: Provider,
    pub base_url: String,
    pub token: Option<String>,
    pub cache: Option<PathBuf>,
    pub expiry: Duration,
    pub timeout: Duration,
    pub requests_per_second: u32,
    pub max_requests: usize,
    pub allow_http: bool,
    pub include_private: bool,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let endpoint = Endpoint::parse(&self.base_url)?;
        if self.base_url.contains(['?', '#']) {
            return Err(Error::Config("enrichment base URL cannot contain a query or fragment; use a bearer-token environment variable".into()));
        }
        if !endpoint.tls && (!self.allow_http || self.token.is_some()) {
            return Err(Error::Config("remote enrichment requires HTTPS; --allow-http permits unauthenticated local/custom endpoints only".into()));
        }
        if self.provider != Provider::Json && self.include_private {
            return Err(Error::Config(
                "nonpublic enrichment is supported only by custom JSON providers".into(),
            ));
        }
        if self.provider == Provider::RipeStat && self.token.is_some() {
            return Err(Error::Config(
                "RIPEstat does not use bearer authentication".into(),
            ));
        }
        if self.provider == Provider::IpinfoLite && self.token.is_none() {
            return Err(Error::Config(
                "IPinfo Lite requires a token and only supports public-IP lookups here".into(),
            ));
        }
        if let Some(token) = &self.token {
            if token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(Error::Config("invalid enrichment bearer token (empty, oversized, or contains whitespace/control characters)".into()));
            }
        }
        if self.timeout.is_zero()
            || self.timeout > Duration::from_secs(30)
            || self.expiry > Duration::from_secs(86400)
            || !(1..=10).contains(&self.requests_per_second)
            || !(1..=4096).contains(&self.max_requests)
        {
            return Err(Error::Config("enrichment requires timeout <=30s, expiry <=86400s, rate 1..=10/s, request budget 1..=4096".into()));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Local,
    Remote,
    Cache,
    NotFound,
    SkippedNonpublic,
    RequestLimit,
    Cancelled,
    Timeout,
    RateLimited,
    Unauthorized,
    ProviderUnavailable,
    Error,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lookup {
    pub status: Status,
    pub provider: Option<String>,
    pub attribution: Option<String>,
    pub fetched_unix_seconds: Option<u64>,
    pub error: Option<String>,
}
impl Lookup {
    pub fn local() -> Self {
        Self {
            status: Status::Local,
            provider: None,
            attribution: None,
            fetched_unix_seconds: None,
            error: None,
        }
    }
    pub fn failed(&self) -> bool {
        matches!(
            self.status,
            Status::Error
                | Status::Timeout
                | Status::Unauthorized
                | Status::RateLimited
                | Status::ProviderUnavailable
        )
    }
}
pub struct Enriched {
    pub metadata: Database,
    pub lookups: BTreeMap<IpAddr, Lookup>,
    pub cache_error: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Cache {
    version: u8,
    provider: Provider,
    base_url: String,
    entries: BTreeMap<IpAddr, Cached>,
}
#[derive(Serialize, Deserialize)]
struct Cached {
    fetched: u64,
    metadata: Metadata,
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Conservative disclosure policy, not a comprehensive routability database.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || ip.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}

pub async fn enrich(
    config: &Config,
    client: &Client,
    ips: &BTreeSet<IpAddr>,
    local: &Database,
    cancel: &Cancellation,
) -> Result<Enriched> {
    config.validate()?;
    if ips.len() > 100_000 {
        return Err(Error::Config("enrichment candidate limit is 100000".into()));
    }
    let base = config.base_url.trim_end_matches('/').to_owned();
    let now = unix_seconds();
    let mut cache = Cache {
        version: 1,
        provider: config.provider,
        base_url: base.clone(),
        entries: BTreeMap::new(),
    };
    if let Some(path) = &config.cache {
        if let Ok(bytes) = read_bounded(path, MAX_CACHE) {
            if let Ok(mut stored) = serde_json::from_slice::<Cache>(&bytes) {
                if stored.version == 1
                    && stored.provider == config.provider
                    && stored.base_url == base
                    && stored.entries.len() <= 4096
                {
                    stored.entries.retain(|_, entry| {
                        now >= entry.fetched
                            && now - entry.fetched < config.expiry.as_secs()
                            && validate(&entry.metadata).is_ok()
                    });
                    cache = stored;
                }
            }
        }
    }
    let mut report = Enriched {
        metadata: BTreeMap::new(),
        lookups: BTreeMap::new(),
        cache_error: None,
    };
    let rate = RateLimiter::new(config.requests_per_second)?;
    let mut requests = 0;
    let mut provider_stopped = false;
    for &ip in ips {
        if let Some(metadata) = local.get(&ip) {
            validate(metadata)?;
            report.metadata.insert(ip, metadata.clone());
            report.lookups.insert(ip, Lookup::local());
            continue;
        }
        let mut lookup = Lookup {
            status: Status::Remote,
            provider: Some(config.provider.name().into()),
            attribution: config.provider.attribution(),
            fetched_unix_seconds: None,
            error: None,
        };
        if !config.include_private && !public_address(ip) {
            lookup.status = Status::SkippedNonpublic;
        } else if let Some(entry) = cache.entries.get(&ip) {
            lookup.status = Status::Cache;
            lookup.fetched_unix_seconds = Some(entry.fetched);
            report.metadata.insert(ip, entry.metadata.clone());
        } else if cancel.is_cancelled() {
            lookup.status = Status::Cancelled;
        } else if provider_stopped {
            lookup.status = Status::ProviderUnavailable;
        } else if requests >= config.max_requests {
            lookup.status = Status::RequestLimit;
        } else if rate.acquire(cancel).await.is_err() {
            lookup.status = Status::Cancelled;
        } else {
            requests += 1;
            // Only the requested IP is sent; no probe statistics or source metadata.
            let url = if config.provider == Provider::RipeStat {
                format!("{base}?resource={ip}&max_related=0&sourceapp=tcp-bench-rs")
            } else {
                format!("{base}/{ip}")
            };
            let result = cancel
                .run(async {
                    tokio::time::timeout(config.timeout, async {
                        let mut response = client
                            .get_with_bearer(&url, None, config.timeout, config.token.as_deref())
                            .await?;
                        let bytes = response.collect(MAX_RESPONSE).await?;
                        decode(config.provider, ip, &bytes)
                    })
                    .await
                    .map_err(|_| Error::Timeout("remote enrichment"))?
                })
                .await;
            match result {
                Ok(Some(metadata)) => {
                    let fetched = unix_seconds();
                    lookup.fetched_unix_seconds = Some(fetched);
                    if cache.entries.len() >= 4096 {
                        cache.entries.pop_first();
                    }
                    cache.entries.insert(
                        ip,
                        Cached {
                            fetched,
                            metadata: metadata.clone(),
                        },
                    );
                    report.metadata.insert(ip, metadata);
                }
                Ok(None) | Err(Error::HttpStatus(404)) => lookup.status = Status::NotFound,
                Err(Error::Cancelled) => lookup.status = Status::Cancelled,
                Err(Error::Timeout(_)) => lookup.status = Status::Timeout,
                Err(Error::HttpStatus(429)) => {
                    lookup.status = Status::RateLimited;
                    provider_stopped = true;
                }
                Err(Error::HttpStatus(401 | 403)) => {
                    lookup.status = Status::Unauthorized;
                    provider_stopped = true;
                }
                Err(error) => {
                    lookup.status = Status::Error;
                    lookup.error = Some(error.to_string());
                }
            }
        }
        report.lookups.insert(ip, lookup);
    }
    if let Some(path) = &config.cache {
        // Never write partial/bogus remote payloads or credentials into the cache.
        let result = serde_json::to_vec(&cache)
            .map_err(Error::from)
            .and_then(|bytes| {
                if bytes.len() > MAX_CACHE {
                    return Err(Error::Config("enrichment cache exceeds 8 MiB".into()));
                }
                write_cache(path, &bytes)
            });
        if let Err(error) = result {
            report.cache_error = Some(error.to_string());
        }
    }
    Ok(report)
}

#[derive(Deserialize)]
struct JsonRecord {
    ip: IpAddr,
    asn: Option<u32>,
    organization: Option<String>,
    location: Option<String>,
}
#[derive(Deserialize)]
struct IpinfoRecord {
    ip: IpAddr,
    asn: Option<String>,
    as_name: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    #[serde(default)]
    bogon: bool,
}
pub fn decode(provider: Provider, ip: IpAddr, bytes: &[u8]) -> Result<Option<Metadata>> {
    if bytes.len() > MAX_RESPONSE {
        return Err(Error::Http("enrichment response exceeds 16 KiB".into()));
    }
    let invalid = || Error::Http("invalid enrichment JSON or field types".into());
    let (received, metadata) = match provider {
        Provider::RipeStat => return decode_ripe(ip, bytes),
        Provider::Json => {
            let record: JsonRecord = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            (
                record.ip,
                Metadata {
                    asn: record.asn,
                    organization: record.organization,
                    location: record.location,
                },
            )
        }
        Provider::IpinfoLite => {
            let record: IpinfoRecord = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if record.ip != ip {
                return Err(Error::Http(
                    "enrichment response IP does not match requested IP".into(),
                ));
            }
            if record.bogon {
                return Ok(None);
            }
            let asn = record
                .asn
                .map(|asn| {
                    asn.strip_prefix("AS")
                        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                        .and_then(|n| n.parse::<u32>().ok())
                        .ok_or_else(invalid)
                })
                .transpose()?;
            if record.country_code.as_ref().is_some_and(|code| {
                code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase())
            }) {
                return Err(invalid());
            }
            (
                record.ip,
                Metadata {
                    asn,
                    organization: record.as_name,
                    location: record.country.or(record.country_code),
                },
            )
        }
    };
    if received != ip {
        return Err(Error::Http(
            "enrichment response IP does not match requested IP".into(),
        ));
    }
    validate(&metadata).map_err(|_| invalid())?;
    if metadata.asn.is_none() && metadata.organization.is_none() && metadata.location.is_none() {
        return Ok(None);
    }
    Ok(Some(metadata))
}

fn decode_ripe(ip: IpAddr, bytes: &[u8]) -> Result<Option<Metadata>> {
    #[derive(Deserialize)]
    struct Reply {
        status: String,
        data: Data,
    }
    #[derive(Deserialize)]
    struct Data {
        resource: String,
        announced: bool,
        asns: Vec<Asn>,
    }
    #[derive(Deserialize)]
    struct Asn {
        asn: u32,
        holder: Option<String>,
    }
    let invalid = || Error::Http("invalid RIPEstat prefix response".into());
    let reply: Reply = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if reply.status != "ok" || reply.data.asns.len() > 16 {
        return Err(invalid());
    }
    let (prefix, length) = reply.data.resource.split_once('/').ok_or_else(invalid)?;
    let prefix: IpAddr = prefix.parse().map_err(|_| invalid())?;
    let length: u32 = length.parse().map_err(|_| invalid())?;
    let matches = match (ip, prefix) {
        (IpAddr::V4(ip), IpAddr::V4(prefix)) if length <= 32 => {
            let mask = u32::MAX.checked_shl(32 - length).unwrap_or(0);
            u32::from(ip) & mask == u32::from(prefix)
                && u32::from(prefix) & mask == u32::from(prefix)
        }
        (IpAddr::V6(ip), IpAddr::V6(prefix)) if length <= 128 => {
            let mask = u128::MAX.checked_shl(128 - length).unwrap_or(0);
            u128::from(ip) & mask == u128::from(prefix)
                && u128::from(prefix) & mask == u128::from(prefix)
        }
        _ => false,
    };
    if !matches {
        return Err(Error::Http(
            "RIPEstat prefix does not contain the requested IP".into(),
        ));
    }
    if !reply.data.announced || reply.data.asns.is_empty() {
        return Ok(None);
    }
    for origin in &reply.data.asns {
        validate(&Metadata {
            asn: Some(origin.asn),
            organization: origin.holder.clone(),
            location: None,
        })
        .map_err(|_| invalid())?;
    }
    // Multi-origin prefixes do not have a uniquely attributable ASN.
    let metadata = if reply.data.asns.len() == 1 {
        let origin = &reply.data.asns[0];
        Metadata {
            asn: Some(origin.asn),
            organization: origin.holder.clone(),
            location: None,
        }
    } else {
        Metadata {
            asn: None,
            organization: Some(format!(
                "Multiple BGP origins: {}",
                reply
                    .data
                    .asns
                    .iter()
                    .map(|a| format!("AS{}", a.asn))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            location: None,
        }
    };
    validate(&metadata).map_err(|_| invalid())?;
    Ok(Some(metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ripe_prefix_binding_and_multiple_origins() {
        let record = serde_json::json!({"status":"ok","data":{"resource":"8.8.8.0/24","announced":true,"asns":[{"asn":64500,"holder":"Fixture"}]}});
        let decode = |value: &serde_json::Value, ip: &str| {
            super::decode(
                Provider::RipeStat,
                ip.parse().unwrap(),
                &serde_json::to_vec(value).unwrap(),
            )
        };
        assert_eq!(
            decode(&record, "8.8.8.8").unwrap().unwrap().asn,
            Some(64500)
        );
        assert!(decode(&record, "8.8.4.4").is_err());
        let mut value = record.clone();
        value["data"]["resource"] = serde_json::json!("8.8.8.1/24");
        assert!(decode(&value, "8.8.8.8").is_err());
        value["data"]["resource"] = serde_json::json!("2001:db8::/32");
        assert!(decode(&value, "2001:db8::1").is_ok());
        assert!(decode(&value, "8.8.8.8").is_err());
        value = record.clone();
        value["data"]["asns"] =
            serde_json::json!([{"asn":64500,"holder":"A"},{"asn":64501,"holder":"B"}]);
        let multi = decode(&value, "8.8.8.8").unwrap().unwrap();
        assert_eq!(multi.asn, None);
        assert!(multi.organization.unwrap().contains("AS64501"));
        value["data"]["announced"] = serde_json::json!(false);
        assert!(decode(&value, "8.8.8.8").unwrap().is_none());
    }
    #[test]
    fn response_binding_and_validation() {
        let ip = "1.1.1.1".parse().unwrap();
        let value=decode(Provider::IpinfoLite,ip,br#"{"ip":"1.1.1.1","asn":"AS64500","as_name":"Test","country_code":"GB","country":"Test country"}"#).unwrap().unwrap();
        assert_eq!(value.asn, Some(64500));
        for bad in [
            br#"{"ip":"1.0.0.1","asn":64500}"#.as_slice(),
            br#"{"ip":"1.1.1.1","asn":0}"#,
            br#"{"ip":"1.1.1.1","organization":"bad\ntext"}"#,
        ] {
            assert!(decode(Provider::Json, ip, bad).is_err());
        }
    }
    #[test]
    fn nonpublic_addresses_are_not_disclosed() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_address(ip.parse().unwrap()));
        }
    }
}
