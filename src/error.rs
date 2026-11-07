#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("iPerf3: {0}")]
    Iperf(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("node data: {0}")]
    Nodes(String),
    #[error("unsupported capability: {0}")]
    Unsupported(String),
    #[error("raw sockets require Linux CAP_NET_RAW (or root): {0}")]
    Privilege(std::io::Error),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP/TLS: {0}")]
    Http(String),
    #[error("HTTP status {0}; expected a complete successful response (redirects disabled)")]
    HttpStatus(u16),
    #[error("deadline exceeded: {0}")]
    Timeout(&'static str),
    #[error("cancelled")]
    Cancelled,
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
