//! Opt-in TcpQuality report publication. No ranking sessions or implicit IP discovery.
use crate::{
    Error, Result,
    http::{Client, Endpoint},
    report::{Measurement, Report},
    scheduler::Cancellation,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
mod archive;
pub mod csv;
mod label;

pub const DEFAULT_URL: &str = "https://tcpquality.ibsgss.uk/generate";
pub struct Config {
    pub url: String,
    pub timeout: Duration,
    pub allow_http: bool,
    pub public_ipv4: Option<Ipv4Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
    pub debug: bool,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let endpoint = Endpoint::parse(&self.url)?;
        if !endpoint.tls && !self.allow_http {
            return Err(Error::Config(
                "report upload requires HTTPS (or explicit --allow-http for a local server)".into(),
            ));
        }
        if endpoint.path != "/generate"
            && (!endpoint.path.ends_with("/generate") || endpoint.path.contains('?'))
        {
            return Err(Error::Config(
                "report URL must end in /generate without a query".into(),
            ));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(120) {
            return Err(Error::Config(
                "upload timeout must be 1..=120 seconds".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub id: String,
    pub url: String,
    pub today_uses: Option<u64>,
    pub total_uses: Option<u64>,
    pub rank_updated: Option<bool>,
    pub rank_reject_reason: Option<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub endpoint: String,
    pub status: Measurement<()>,
}

pub(crate) fn timestamp(seconds: u64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(seconds).map_err(|_| Error::Config("report timestamp overflow".into()))?,
    )
    .map_err(|e| Error::Config(format!("report timestamp: {e}")))?
    .format(&Rfc3339)
    .map_err(|e| Error::Config(format!("format report timestamp: {e}")))
}
fn report_time(seconds: u64) -> Result<String> {
    let date = OffsetDateTime::from_unix_timestamp(
        i64::try_from(seconds).map_err(|_| Error::Config("report timestamp overflow".into()))?,
    )
    .map_err(|e| Error::Config(format!("report timestamp: {e}")))?
    .to_offset(UtcOffset::from_hms(8, 0, 0).map_err(|e| Error::Config(e.to_string()))?);
    Ok(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} CST",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    ))
}
fn parse_receipt(bytes: &[u8], allow_http: bool) -> Result<Receipt> {
    let mut receipt: Receipt = serde_json::from_slice(bytes)?;
    if receipt.id.is_empty()
        || receipt.id.len() > 128
        || !receipt
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Http("invalid report ID in upload response".into()));
    }
    if !Endpoint::parse(&receipt.url)?.tls && !allow_http {
        return Err(Error::Http("upload returned an insecure report URL".into()));
    }
    if receipt.url.chars().any(char::is_control)
        || receipt
            .rank_reject_reason
            .as_ref()
            .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
    {
        return Err(Error::Http("invalid text in upload response".into()));
    }
    // Only the client may claim that an attachment was uploaded.
    receipt.attachments.clear();
    Ok(receipt)
}
pub async fn upload(
    config: &Config,
    client: &Client,
    report: &Report,
    cancel: &Cancellation,
) -> Result<Receipt> {
    config.validate()?;
    let csv = csv::encode(report)?;
    let report_time = report_time(report.started_unix_seconds)?;
    let finished = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| Error::Config(e.to_string()))?;
    let ip4 = config
        .public_ipv4
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let ip6 = config
        .public_ipv6
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + config.timeout;
    let response = cancel
        .run(async {
            tokio::time::timeout_at(deadline, async {
                let mut response = client
                    .post(
                        &config.url,
                        &[
                            ("Content-Type", "text/csv; charset=utf-8"),
                            ("X-Report-Time", &report_time),
                            ("X-TcpQuality-Public-IPv4", &ip4),
                            ("X-TcpQuality-Public-IPv6", &ip6),
                            ("X-TcpQuality-Rank-Finished-At", &finished),
                            (
                                "X-TcpQuality-Rank-Disabled-Reason",
                                "tcp-bench-rs-report-only",
                            ),
                        ],
                        &csv,
                        config.timeout,
                    )
                    .await?;
                response.collect(64 * 1024).await
            })
            .await
            .map_err(|_| Error::Timeout("report upload"))?
        })
        .await?;
    let mut receipt = parse_receipt(&response, config.allow_http)?;
    let base = config
        .url
        .strip_suffix("/generate")
        .ok_or_else(|| Error::Config("invalid report endpoint".into()))?;
    // A failure after /generate must preserve the already-created shareable link.
    let bundles = archive::bundles(report, &receipt.id, config.debug);
    match bundles {
        Err(error) => receipt.attachments.push(Attachment {
            endpoint: "prepare attachments".into(),
            status: Measurement::from_result(Err(error)),
        }),
        Ok(bundles) => {
            for bundle in bundles {
                let endpoint = format!("{base}/{}", bundle.path);
                let result = cancel
                    .run(async {
                        tokio::time::timeout_at(deadline, async {
                            let mut response = client
                                .post(
                                    &endpoint,
                                    &[("Content-Type", "application/gzip")],
                                    &bundle.bytes,
                                    config.timeout,
                                )
                                .await?;
                            response.collect(64 * 1024).await?;
                            Ok(())
                        })
                        .await
                        .map_err(|_| Error::Timeout("report attachment upload"))?
                    })
                    .await;
                receipt.attachments.push(Attachment {
                    endpoint,
                    status: Measurement::from_result(result),
                });
            }
        }
    }
    Ok(receipt)
}
