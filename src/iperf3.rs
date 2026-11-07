//! Independently implemented single-stream iPerf3 TCP client. No subprocesses.
//! Protocol sources and intentionally unsupported modes: docs/iperf3.md.
use crate::{
    Error, Result,
    scheduler::Cancellation,
    tcp_stats::{self, TcpStats},
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

const PARAM_EXCHANGE: u8 = 9;
const CREATE_STREAMS: u8 = 10;
const TEST_START: u8 = 1;
const TEST_RUNNING: u8 = 2;
const TEST_END: u8 = 4;
const CLIENT_TERMINATE: u8 = 12;
const EXCHANGE_RESULTS: u8 = 13;
const DISPLAY_RESULTS: u8 = 14;
const DONE: u8 = 16;
const MAX_JSON: usize = 64 * 1024;
const BLOCK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub peer: SocketAddr,
    pub direction: Direction,
    pub max_bytes: u64,
    pub duration: Duration,
    pub setup_timeout: Duration,
    /// Application pacing in bits/second; zero explicitly requests unlimited.
    pub bitrate: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResult {
    pub role: String,
    pub bytes: u64,
    pub seconds: Option<f64>,
    pub bits_per_second: Option<f64>,
    /// Only present when the server was the sender and advertised this capability.
    pub sender_retransmissions: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transfer {
    pub protocol: String,
    pub direction: Direction,
    pub peer: SocketAddr,
    pub stream_bytes: u64,
    pub stream_seconds: f64,
    pub bits_per_second: Option<f64>,
    pub requested_bitrate: u64,
    pub stop_reason: String,
    pub setup_ms: f64,
    pub tcp_before: TcpStats,
    pub tcp_after: TcpStats,
    pub local_sender_retransmissions_delta: Option<u32>,
    pub server: Option<ServerResult>,
    pub result_exchange: String,
    pub error: Option<String>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.peer.port() == 0
            || self.max_bytes == 0
            || self.max_bytes > 1_099_511_627_776
            || self.duration.is_zero()
            || self.duration > Duration::from_secs(600)
            || self.setup_timeout.is_zero()
            || self.setup_timeout > Duration::from_secs(60)
            || self.bitrate > 100_000_000_000
        {
            return Err(Error::Config("iPerf3 requires nonzero port, 1..=1 TiB, duration <=600s, setup timeout <=60s, and bitrate <=100 Gbit/s".into()));
        }
        Ok(())
    }
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Iperf(message.into())
}
async fn state(stream: &mut TcpStream) -> Result<u8> {
    let state = stream
        .read_u8()
        .await
        .map_err(|e| Error::io("read iPerf3 control state", e))?;
    match state {
        255 => Err(protocol(
            "server denied this session (busy or access denied)",
        )),
        254 => {
            let code = stream
                .read_u32()
                .await
                .map_err(|e| Error::io("iPerf3 server error code", e))?;
            let errno = stream
                .read_u32()
                .await
                .map_err(|e| Error::io("iPerf3 server errno", e))?;
            Err(protocol(format!(
                "server error {code}, errno {errno}; authenticated endpoints are not supported"
            )))
        }
        11 => Err(protocol("server terminated the test")),
        value => Ok(value),
    }
}
async fn expect(stream: &mut TcpStream, wanted: u8) -> Result<()> {
    let actual = state(stream).await?;
    if actual != wanted {
        return Err(protocol(format!(
            "expected control state {wanted}, received {actual}"
        )));
    }
    Ok(())
}
async fn write_json(stream: &mut TcpStream, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_JSON {
        return Err(protocol("outgoing control JSON exceeds 64 KiB"));
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|e| Error::io("iPerf3 JSON length", e))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| Error::io("iPerf3 JSON body", e))
}
async fn read_json(stream: &mut TcpStream) -> Result<Value> {
    let len = stream
        .read_u32()
        .await
        .map_err(|e| Error::io("iPerf3 result length", e))? as usize;
    if len == 0 || len > MAX_JSON {
        return Err(protocol(
            "server control JSON length must be 1..=65536 bytes",
        ));
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| Error::io("iPerf3 result body", e))?;
    serde_json::from_slice(&bytes).map_err(|_| protocol("malformed server result JSON"))
}
fn cookie() -> Result<[u8; 37]> {
    let mut random = [0; 18];
    getrandom::getrandom(&mut random).map_err(|e| protocol(format!("OS random source: {e}")))?;
    let mut cookie = [0; 37];
    let hex = b"0123456789abcdef";
    for (i, byte) in random.iter().enumerate() {
        cookie[i * 2] = hex[(byte >> 4) as usize];
        cookie[i * 2 + 1] = hex[(byte & 15) as usize];
    }
    Ok(cookie)
}
async fn handshake(config: &Config) -> Result<(TcpStream, TcpStream)> {
    let cookie = cookie()?;
    let mut control = TcpStream::connect(config.peer)
        .await
        .map_err(|e| Error::io("connect iPerf3 control socket", e))?;
    control
        .set_nodelay(true)
        .map_err(|e| Error::io("iPerf3 control TCP_NODELAY", e))?;
    control
        .write_all(&cookie)
        .await
        .map_err(|e| Error::io("iPerf3 control cookie", e))?;
    expect(&mut control, PARAM_EXCHANGE).await?;
    let mut parameters = json!({"tcp":true,"omit":0,"time":config.duration.as_secs_f64().ceil() as u64,
        "num":config.max_bytes,"parallel":1,"len":(BLOCK as u64).min(config.max_bytes),
        "bandwidth":config.bitrate,"pacing_timer":1000,"client_version":concat!("tcp-bench-rs/",env!("CARGO_PKG_VERSION"))});
    // iPerf3 interprets presence of "reverse", even false, as reverse mode.
    if config.direction == Direction::Download {
        parameters["reverse"] = json!(true);
    }
    write_json(&mut control, &parameters).await?;
    expect(&mut control, CREATE_STREAMS).await?;
    let mut data = TcpStream::connect(config.peer)
        .await
        .map_err(|e| Error::io("connect iPerf3 data socket", e))?;
    data.write_all(&cookie)
        .await
        .map_err(|e| Error::io("iPerf3 stream cookie", e))?;
    expect(&mut control, TEST_START).await?;
    expect(&mut control, TEST_RUNNING).await?;
    Ok((control, data))
}

pub async fn run(config: &Config, cancel: &Cancellation) -> Result<Transfer> {
    config.validate()?;
    let setup = Instant::now();
    let (mut control, mut data) = cancel
        .run(async {
            tokio::time::timeout(config.setup_timeout, handshake(config))
                .await
                .map_err(|_| Error::Timeout("iPerf3 negotiation"))?
        })
        .await?;
    let setup_ms = setup.elapsed().as_secs_f64() * 1000.0;
    let tcp_before = tcp_stats::sample(&data);
    let mut buffer = vec![0; BLOCK];
    if config.direction == Direction::Upload {
        getrandom::getrandom(&mut buffer)
            .map_err(|e| protocol(format!("OS payload random source: {e}")))?;
    }
    let started = Instant::now();
    let deadline = started + config.duration;
    let mut bytes = 0u64;
    let mut error = None;
    let stop_reason = {
        // Keep this future alive across data operations: a split server-error frame
        // must not be partially consumed then discarded when a data read wins.
        let event = state(&mut control);
        tokio::pin!(event);
        loop {
            if cancel.is_cancelled() {
                break "cancelled";
            }
            if bytes == config.max_bytes {
                break "byte_limit";
            }
            if Instant::now() >= deadline {
                break "duration_limit";
            }
            let limit = (buffer.len() as u64).min(config.max_bytes - bytes) as usize;
            let pace = if config.bitrate > 0 && config.direction == Direction::Upload {
                started + Duration::from_secs_f64(bytes as f64 * 8.0 / config.bitrate as f64)
            } else {
                started
            };
            let io = async {
                if config.direction == Direction::Upload {
                    tokio::time::sleep_until(pace).await;
                    data.write(&buffer[..limit]).await
                } else {
                    data.read(&mut buffer[..limit]).await
                }
            };
            let result = tokio::select! {biased;
                ()=cancel.cancelled()=>break "cancelled",
                ()=tokio::time::sleep_until(deadline)=>break "duration_limit",
                message=&mut event=>{
                    error=Some(match message{Ok(state)=>format!("unexpected iPerf3 state {state} during transfer"),Err(e)=>e.to_string()});
                    break "error";
                },
                result=io=>result,
            };
            match result {
                Ok(0) => {
                    error = Some("iPerf3 data stream closed before the requested limit".into());
                    break "error";
                }
                Ok(n) => bytes += n as u64,
                Err(e) => {
                    error = Some(format!("iPerf3 data I/O: {e}"));
                    break "error";
                }
            }
        }
    };
    let seconds = started.elapsed().as_secs_f64();
    let tcp_after = tcp_stats::sample(&data);
    let delta = tcp_before
        .local_sender_total_retransmissions
        .zip(tcp_after.local_sender_total_retransmissions)
        .map(|(a, b)| b.wrapping_sub(a));
    let mut transfer = Transfer {
        protocol: "iperf3_tcp".into(),
        direction: config.direction,
        peer: config.peer,
        stream_bytes: bytes,
        stream_seconds: seconds,
        bits_per_second: (seconds > 0.0).then(|| bytes as f64 * 8.0 / seconds),
        requested_bitrate: config.bitrate,
        stop_reason: stop_reason.into(),
        setup_ms,
        tcp_before,
        tcp_after,
        local_sender_retransmissions_delta: delta,
        server: None,
        result_exchange: "not_attempted".into(),
        error,
    };
    if stop_reason == "cancelled" || stop_reason == "error" {
        let _ = control.try_write(&[CLIENT_TERMINATE]);
        transfer.result_exchange = if stop_reason == "cancelled" {
            "cancelled"
        } else {
            "not_attempted"
        }
        .into();
        return Ok(transfer);
    }
    let exchange=cancel.run(async {
        tokio::time::timeout(config.setup_timeout,async {
            control.write_u8(TEST_END).await.map_err(|e|Error::io("send iPerf3 TEST_END",e))?;
            expect(&mut control,EXCHANGE_RESULTS).await?;
            let sender_retrans=if config.direction==Direction::Upload {delta.map(i64::from).unwrap_or(-1)}else{-1};
            // CPU utilization is unmeasured: -1 is an explicit wire-only sentinel.
            let results=json!({"cpu_util_total":-1,"cpu_util_user":-1,"cpu_util_system":-1,
                "sender_has_retransmits":if sender_retrans>=0{1}else{-1},
                "streams":[{"id":1,"bytes":bytes,"retransmits":sender_retrans,"jitter":0,"errors":0,"packets":0,
                    "start_time":0,"end_time":seconds}]});
            write_json(&mut control,&results).await?;
            let server=parse_results(&read_json(&mut control).await?,config.direction)?;
            expect(&mut control,DISPLAY_RESULTS).await?;
            control.write_u8(DONE).await.map_err(|e|Error::io("send iPerf3 DONE",e))?;
            Ok(server)
        }).await.map_err(|_|Error::Timeout("iPerf3 result exchange"))?
    }).await;
    match exchange {
        Ok(server) => {
            transfer.server = Some(server);
            transfer.result_exchange = "complete".into();
        }
        Err(Error::Cancelled) => {
            transfer.result_exchange = "cancelled".into();
            let _ = control.try_write(&[CLIENT_TERMINATE]);
        }
        Err(e) => {
            transfer.result_exchange = "error".into();
            transfer.error = Some(e.to_string());
            let _ = control.try_write(&[CLIENT_TERMINATE]);
        }
    }
    // Keep the stream open through result exchange; premature EOF can make a
    // conforming server abort instead of returning its final measurements.
    drop(data);
    Ok(transfer)
}

fn integer(value: &Value, name: &str) -> Result<u64> {
    let n = value
        .as_f64()
        .ok_or_else(|| protocol(format!("missing or nonnumeric server {name}")))?;
    if !n.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&n) || n.fract() != 0.0 {
        return Err(protocol(format!("invalid server {name}")));
    }
    Ok(n as u64)
}
fn unavailable(n: f64) -> bool {
    // iPerf3 3.12's integer JSON serialization can encode -1 as UINT64_MAX,
    // which rounds to 2^64 when read as a double. Neither encoding is a count.
    n == -1.0 || n == u64::MAX as f64
}
fn parse_results(value: &Value, direction: Direction) -> Result<ServerResult> {
    let streams = value
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol("server results have no streams array"))?;
    if streams.len() != 1 || integer(&streams[0]["id"], "stream id")? != 1 {
        return Err(protocol("expected exactly one server stream with id 1"));
    }
    let stream = &streams[0];
    let bytes = integer(&stream["bytes"], "bytes")?;
    let capability = value
        .get("sender_has_retransmits")
        .and_then(Value::as_f64)
        .ok_or_else(|| protocol("missing server retransmission capability"))?;
    if ![0.0, 1.0].contains(&capability) && !unavailable(capability) {
        return Err(protocol(format!(
            "invalid server retransmission capability {capability}"
        )));
    }
    let retransmissions = if direction == Direction::Download && capability == 1.0 {
        match stream.get("retransmits") {
            Some(value) if value.as_f64().is_some_and(unavailable) => None,
            Some(value) => Some(integer(value, "retransmits")?),
            None => return Err(protocol("missing advertised server retransmissions")),
        }
    } else {
        None
    };
    let seconds = match (stream.get("start_time"), stream.get("end_time")) {
        (None, None) => None,
        (Some(a), Some(b)) => {
            let a = a
                .as_f64()
                .ok_or_else(|| protocol("invalid server start time"))?;
            let b = b
                .as_f64()
                .ok_or_else(|| protocol("invalid server end time"))?;
            if !a.is_finite() || !b.is_finite() || a < 0.0 || b < a || b - a > 3600.0 {
                return Err(protocol("invalid server timing interval"));
            }
            Some(b - a)
        }
        _ => return Err(protocol("incomplete server timing interval")),
    };
    Ok(ServerResult {
        role: if direction == Direction::Download {
            "sender"
        } else {
            "receiver"
        }
        .into(),
        bytes,
        seconds,
        bits_per_second: seconds.filter(|&s| s > 0.0).map(|s| bytes as f64 * 8.0 / s),
        sender_retransmissions: retransmissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn result_validation_and_sender_identity() {
        let valid = json!({"sender_has_retransmits":1,"streams":[{"id":1,"bytes":9000,"retransmits":4,"start_time":0,"end_time":2}]});
        let result = parse_results(&valid, Direction::Download).unwrap();
        assert_eq!(result.sender_retransmissions, Some(4));
        assert_eq!(result.bits_per_second, Some(36000.0));
        assert_eq!(
            parse_results(&valid, Direction::Upload)
                .unwrap()
                .sender_retransmissions,
            None
        );
        for (field, bad) in [
            ("id", json!(2)),
            ("bytes", json!(-1)),
            ("bytes", json!(1.5)),
            ("retransmits", json!(-2)),
            ("end_time", json!(-1)),
        ] {
            let mut invalid = valid.clone();
            invalid["streams"][0][field] = bad;
            assert!(parse_results(&invalid, Direction::Download).is_err());
        }
    }
}
