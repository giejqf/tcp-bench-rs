//! Single-connection HTTP/1.1 with bounded framing. No redirects, proxies or decompression.
use crate::{
    Error, Result,
    tcp_stats::{self, TcpStats},
};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::TcpStream,
    time::Instant,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

const MAX_HEADERS: usize = 32768;
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub tls: bool,
    pub authority: String,
}
impl Endpoint {
    pub fn parse(url: &str) -> Result<Self> {
        if url.len() > 8192 || url.contains('#') {
            return Err(Error::Http(
                "URL exceeds 8192 bytes or contains a fragment".into(),
            ));
        }
        let uri: ::http::Uri = url
            .parse()
            .map_err(|e| Error::Http(format!("invalid URL: {e}")))?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(Error::Http("URL must use http:// or https://".into())),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| Error::Http("URL has no host".into()))?;
        if authority.as_str().contains('@') {
            return Err(Error::Http("URL credentials are not supported".into()));
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if host.is_empty()
            || (!host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                && host.parse::<IpAddr>().is_err())
        {
            return Err(Error::Http(
                "host must be an ASCII DNS name or IP literal".into(),
            ));
        }
        let port = if let Some(port) = authority.port() {
            port.as_str()
                .parse::<u16>()
                .map_err(|_| Error::Http("invalid URL port".into()))?
        } else if tls {
            443
        } else {
            80
        };
        if port == 0 {
            return Err(Error::Http("URL port must be nonzero".into()));
        }
        Ok(Self {
            host,
            port,
            path: uri.path_and_query().map_or("/", |p| p.as_str()).into(),
            tls,
            authority: authority.to_string(),
        })
    }
}

enum Transport {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}
impl Transport {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(s) => s,
            Self::Tls(s) => s.get_ref().0,
        }
    }
}
impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
}
impl Default for Client {
    fn default() -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots)
    }
}
impl Client {
    pub fn with_roots(roots: rustls::RootCertStore) -> Self {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports safe TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: Arc::new(config),
        }
    }
    pub async fn get(
        &self,
        url: &str,
        fixed_ip: Option<IpAddr>,
        setup_timeout: Duration,
    ) -> Result<Response> {
        self.get_with_bearer(url, fixed_ip, setup_timeout, None)
            .await
    }
    /// Credentials are sent only in a validated header over authenticated TLS.
    /// Redirects remain disabled, so credentials cannot migrate to another origin.
    pub async fn get_with_bearer(
        &self,
        url: &str,
        fixed_ip: Option<IpAddr>,
        setup_timeout: Duration,
        bearer: Option<&str>,
    ) -> Result<Response> {
        if let Some(token) = bearer {
            if token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(Error::Config("bearer token must contain 1..=4096 printable ASCII characters without whitespace".into()));
            }
            if !Endpoint::parse(url)?.tls {
                return Err(Error::Config("bearer authentication requires HTTPS".into()));
            }
        }
        tokio::time::timeout(setup_timeout, self.open(url, fixed_ip, bearer))
            .await
            .map_err(|_| Error::Timeout("DNS/connect/TLS/HTTP headers"))?
    }
    async fn open(
        &self,
        url: &str,
        fixed_ip: Option<IpAddr>,
        bearer: Option<&str>,
    ) -> Result<Response> {
        let endpoint = Endpoint::parse(url)?;
        let started = Instant::now();
        let addresses = if let Some(ip) = fixed_ip {
            vec![SocketAddr::new(ip, endpoint.port)]
        } else {
            tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
                .await
                .map_err(|e| Error::io("resolve HTTP host", e))?
                .take(16)
                .collect::<Vec<_>>()
        };
        let dns_ms = started.elapsed().as_secs_f64() * 1000.0;
        let connect_start = Instant::now();
        let mut connected = None;
        let mut last = None;
        for address in addresses {
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    connected = Some(stream);
                    break;
                }
                Ok(Err(e)) => last = Some(e.to_string()),
                Err(_) => last = Some("connect timeout".into()),
            }
        }
        let stream = connected.ok_or_else(|| {
            Error::Http(format!(
                "could not connect: {}",
                last.unwrap_or_else(|| "DNS returned no addresses".into())
            ))
        })?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::io("TCP_NODELAY", e))?;
        let peer = stream
            .peer_addr()
            .map_err(|e| Error::io("HTTP peer address", e))?;
        let connect_ms = connect_start.elapsed().as_secs_f64() * 1000.0;
        let tls_start = Instant::now();
        let (transport, tls_ms) = if endpoint.tls {
            let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
                .map_err(|e| Error::Http(format!("TLS server name: {e}")))?;
            let stream = TlsConnector::from(self.tls.clone())
                .connect(name, stream)
                .await
                .map_err(|e| Error::Http(format!("TLS handshake/certificate: {e}")))?;
            (
                Transport::Tls(Box::new(stream)),
                Some(tls_start.elapsed().as_secs_f64() * 1000.0),
            )
        } else {
            (Transport::Plain(stream), None)
        };
        let mut reader = BufReader::with_capacity(32768, transport);
        let authorization = bearer
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: tcp-bench-rs/{}\r\n{authorization}Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            endpoint.path,
            endpoint.authority,
            env!("CARGO_PKG_VERSION")
        );
        reader
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::io("HTTP request", e))?;
        reader
            .get_mut()
            .flush()
            .await
            .map_err(|e| Error::io("flush HTTP request", e))?;
        let mut bytes = Vec::new();
        loop {
            let line = read_line(&mut reader, MAX_HEADERS - bytes.len()).await?;
            let end = line == b"\r\n";
            bytes.extend(line);
            if end {
                break;
            }
            if bytes.len() >= MAX_HEADERS {
                return Err(Error::Http("response headers exceed 32 KiB".into()));
            }
        }
        let framing = parse_headers(&bytes)?;
        let stats_before = tcp_stats::sample(reader.get_ref().tcp());
        Ok(Response {
            reader,
            framing,
            chunk_remaining: 0,
            chunk_needs_crlf: false,
            chunk_done: false,
            peer,
            dns_ms,
            connect_ms,
            tls_ms,
            headers_ms: started.elapsed().as_secs_f64() * 1000.0,
            stats_before,
        })
    }
}

enum Framing {
    Length(u64),
    Chunked,
    Close,
}
fn parse_headers(bytes: &[u8]) -> Result<Framing> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    if !response
        .parse(bytes)
        .map_err(|e| Error::Http(format!("invalid HTTP response: {e}")))?
        .is_complete()
    {
        return Err(Error::Http("incomplete HTTP response headers".into()));
    }
    let code = response
        .code
        .ok_or_else(|| Error::Http("missing HTTP status".into()))?;
    if !(200..300).contains(&code) || code == 206 {
        return Err(Error::HttpStatus(code));
    }
    let mut length = None;
    let mut chunked = false;
    let mut transfer_seen = false;
    for header in response.headers {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Error::Http("non-ASCII framing header".into()))?
            .trim();
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Http("invalid or duplicate Content-Length".into()));
            }
            length = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| Error::Http("Content-Length overflow".into()))?,
            );
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_seen || !value.eq_ignore_ascii_case("chunked") {
                return Err(Error::Http(
                    "only a single chunked Transfer-Encoding is supported".into(),
                ));
            }
            transfer_seen = true;
            chunked = true;
        }
        if header.name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(Error::Http("compressed HTTP response refused".into()));
        }
    }
    if chunked && length.is_some() {
        return Err(Error::Http(
            "ambiguous Transfer-Encoding plus Content-Length".into(),
        ));
    }
    if code == 204 {
        return Ok(Framing::Length(0));
    }
    Ok(if chunked {
        Framing::Chunked
    } else if let Some(length) = length {
        Framing::Length(length)
    } else {
        Framing::Close
    })
}

async fn read_line(reader: &mut BufReader<Transport>, limit: usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| Error::io("read HTTP framing", e))?;
        if available.is_empty() {
            return Err(Error::Http("unexpected EOF in HTTP framing".into()));
        }
        let n = available
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if n > limit.saturating_sub(line.len()) {
            return Err(Error::Http("HTTP framing line exceeds limit".into()));
        }
        let end = available[n - 1] == b'\n';
        line.extend_from_slice(&available[..n]);
        reader.consume(n);
        if end {
            if !line.ends_with(b"\r\n") {
                return Err(Error::Http("HTTP requires CRLF framing".into()));
            }
            return Ok(line);
        }
    }
}

pub struct Response {
    reader: BufReader<Transport>,
    framing: Framing,
    chunk_remaining: u64,
    chunk_needs_crlf: bool,
    chunk_done: bool,
    pub peer: SocketAddr,
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: Option<f64>,
    pub headers_ms: f64,
    pub stats_before: TcpStats,
}
impl Response {
    pub fn stats(&self) -> TcpStats {
        tcp_stats::sample(self.reader.get_ref().tcp())
    }
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let limit = match self.framing {
            Framing::Length(0) => return Ok(0),
            Framing::Length(n) => n.min(buffer.len() as u64) as usize,
            Framing::Close => buffer.len(),
            Framing::Chunked => {
                if self.chunk_done {
                    return Ok(0);
                }
                if self.chunk_remaining == 0 {
                    if self.chunk_needs_crlf {
                        let mut crlf = [0; 2];
                        self.reader
                            .read_exact(&mut crlf)
                            .await
                            .map_err(|e| Error::io("chunk terminator", e))?;
                        if crlf != *b"\r\n" {
                            return Err(Error::Http("invalid chunk terminator".into()));
                        }
                    }
                    let line = read_line(&mut self.reader, 1024).await?;
                    let digits = line[..line.len() - 2]
                        .split(|&b| b == b';')
                        .next()
                        .unwrap_or_default();
                    if digits.is_empty()
                        || digits.len() > 16
                        || !digits.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(Error::Http("invalid chunk size".into()));
                    }
                    self.chunk_remaining = u64::from_str_radix(
                        std::str::from_utf8(digits)
                            .map_err(|_| Error::Http("invalid chunk size".into()))?,
                        16,
                    )
                    .map_err(|_| Error::Http("chunk size overflow".into()))?;
                    if self.chunk_remaining == 0 {
                        let mut used = 0;
                        loop {
                            let trailer = read_line(&mut self.reader, MAX_HEADERS - used).await?;
                            used += trailer.len();
                            if trailer == b"\r\n" {
                                break;
                            }
                            if used >= MAX_HEADERS {
                                return Err(Error::Http("trailers exceed 32 KiB".into()));
                            }
                        }
                        self.chunk_done = true;
                        return Ok(0);
                    }
                    self.chunk_needs_crlf = true;
                }
                self.chunk_remaining.min(buffer.len() as u64) as usize
            }
        };
        let n = self
            .reader
            .read(&mut buffer[..limit])
            .await
            .map_err(|e| Error::io("read HTTP body", e))?;
        if n == 0 && !matches!(self.framing, Framing::Close) {
            return Err(Error::Http(
                "response body ended before declared length".into(),
            ));
        }
        match &mut self.framing {
            Framing::Length(left) => *left -= n as u64,
            Framing::Chunked => self.chunk_remaining -= n as u64,
            Framing::Close => {}
        }
        Ok(n)
    }
    pub async fn collect(&mut self, max: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let limit = buffer
                .len()
                .min(max.saturating_sub(body.len()).saturating_add(1));
            let n = self.read(&mut buffer[..limit]).await?;
            if n == 0 {
                return Ok(body);
            }
            if n > max.saturating_sub(body.len()) {
                return Err(Error::Http(format!("response exceeds {max} bytes")));
            }
            body.extend_from_slice(&buffer[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_validation() {
        let endpoint = Endpoint::parse("https://[2001:db8::1]:8443/test?a=b").unwrap();
        assert_eq!(endpoint.host, "2001:db8::1");
        assert_eq!(endpoint.port, 8443);
        for url in [
            "file:///tmp/x",
            "https://user:pass@host/",
            "https://host/#fragment",
            "http://host:0/",
        ] {
            assert!(Endpoint::parse(url).is_err(), "{url}");
        }
    }
    #[test]
    fn ambiguous_framing_rejected() {
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            b"HTTP/1.1 302 Moved\r\nLocation: https://example.com\r\n\r\n",
        ] {
            assert!(parse_headers(bytes).is_err());
        }
    }
    async fn server(reply: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            for part in reply.chunks(3) {
                stream.write_all(part).await.unwrap();
            }
        });
        format!("http://{addr}/")
    }
    #[tokio::test]
    async fn streams_chunked_body() {
        let url=server(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Test: yes\r\n\r\n").await;
        let mut response = Client::default()
            .get(&url, None, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.collect(5).await.unwrap(), b"abcde");
    }
    #[tokio::test]
    async fn refuses_truncation_and_oversized_body() {
        for reply in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef",
        ] {
            let url = server(reply).await;
            let mut response = Client::default()
                .get(&url, None, Duration::from_secs(2))
                .await
                .unwrap();
            assert!(response.collect(5).await.is_err());
        }
    }
}
