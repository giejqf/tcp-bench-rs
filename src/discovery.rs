use crate::{
    Error, Result,
    http::{Client, Endpoint},
    nodes::{self, MAX_NODE_BYTES, Node},
    scheduler::Cancellation,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A named pipe must not block before we can reject its file type.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    if !file
        .metadata()
        .map_err(|e| Error::io("file metadata", e))?
        .is_file()
    {
        return Err(Error::Nodes("input must be a regular file".into()));
    }
    let mut data = Vec::new();
    file.take((max + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|e| Error::io(format!("read {}", path.display()), e))?;
    if data.len() > max {
        return Err(Error::Nodes(format!(
            "{} exceeds {max} bytes",
            path.display()
        )));
    }
    Ok(data)
}
pub fn local(path: &Path) -> Result<Vec<Node>> {
    nodes::parse_tsv(&read_bounded(path, MAX_NODE_BYTES)?)
}
#[derive(Serialize, Deserialize)]
struct Cache {
    version: u8,
    url: String,
    fetched_at: u64,
    tsv: String,
}
pub struct DiscoveryConfig<'a> {
    pub url: &'a str,
    pub scope: &'a str,
    pub cache: Option<&'a Path>,
    pub expiry: Duration,
    pub timeout: Duration,
    pub retries: u8,
    pub allow_http: bool,
}
pub async fn remote(
    config: DiscoveryConfig<'_>,
    client: &Client,
    cancel: &Cancellation,
) -> Result<Vec<Node>> {
    if !matches!(
        config.scope,
        "cdn" | "v4" | "v6" | "cernet" | "all" | "tos" | "apple6" | "telegram"
    ) {
        return Err(Error::Config("unsupported getNodes scope".into()));
    }
    if config.retries > 3
        || config.expiry > Duration::from_secs(86400)
        || config.timeout.is_zero()
        || config.timeout > Duration::from_secs(60)
    {
        return Err(Error::Config(
            "discovery retries <=3, expiry <=86400s, timeout 1..=60s required".into(),
        ));
    }
    let endpoint = Endpoint::parse(config.url)?;
    if !endpoint.tls && !config.allow_http {
        return Err(Error::Config(
            "plain HTTP discovery requires --allow-http".into(),
        ));
    }
    let query = endpoint.path.split_once('?').map_or("", |(_, q)| q);
    if query
        .split('&')
        .any(|part| matches!(part.split('=').next(), Some("format" | "scope")))
    {
        return Err(Error::Config(
            "nodes URL must not already contain format or scope parameters".into(),
        ));
    }
    let url = format!(
        "{}{}format=tsv&scope={}",
        config.url,
        if config.url.contains('?') { "&" } else { "?" },
        config.scope
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Config("system clock predates UNIX epoch".into()))?
        .as_secs();
    if let Some(path) = config.cache {
        if let Ok(bytes) = read_bounded(path, MAX_NODE_BYTES * 3) {
            if let Ok(cache) = serde_json::from_slice::<Cache>(&bytes) {
                if cache.version == 1
                    && cache.url == url
                    && now >= cache.fetched_at
                    && now - cache.fetched_at < config.expiry.as_secs()
                {
                    if let Ok(nodes) = nodes::parse_tsv(cache.tsv.as_bytes()) {
                        return Ok(nodes);
                    }
                }
            }
        }
    }
    let mut last = None;
    for attempt in 0..=config.retries {
        if attempt > 0 {
            cancel
                .run(async {
                    tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
                    Ok(())
                })
                .await?;
        }
        let fetched = cancel
            .run(async {
                tokio::time::timeout(config.timeout, async {
                    let mut response = client.get(&url, None, config.timeout).await?;
                    response.collect(MAX_NODE_BYTES).await
                })
                .await
                .map_err(|_| Error::Timeout("node discovery"))?
            })
            .await;
        match fetched {
            Ok(bytes) => {
                let nodes = nodes::parse_tsv(&bytes)?;
                if let Some(path) = config.cache {
                    let cache = Cache {
                        version: 1,
                        url: url.clone(),
                        fetched_at: now,
                        tsv: String::from_utf8(bytes).map_err(|e| Error::Nodes(e.to_string()))?,
                    };
                    write_cache(path, &serde_json::to_vec(&cache)?)?;
                }
                return Ok(nodes);
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| Error::Nodes("no fetch attempted".into())))
}
pub(crate) fn write_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut random = [0; 8];
    getrandom::getrandom(&mut random).map_err(|e| Error::Nodes(format!("cache nonce: {e}")))?;
    let temp = path.with_extension(format!("tmp-{:016x}", u64::from_ne_bytes(random)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| Error::io("create temporary cache", e))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| Error::io("write node cache", e))?;
        file.sync_all()
            .map_err(|e| Error::io("sync node cache", e))?;
        std::fs::rename(&temp, path).map_err(|e| Error::io("replace node cache", e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
