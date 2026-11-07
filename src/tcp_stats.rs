//! Linux TCP_INFO is a length-versioned ABI; never read fields beyond returned length.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpStats {
    pub status: String,
    pub rtt_us: Option<u32>,
    pub rtt_variance_us: Option<u32>,
    pub send_congestion_window_segments: Option<u32>,
    pub local_sender_total_retransmissions: Option<u32>,
    pub remote_sender_retransmissions: Option<u32>,
}
impl TcpStats {
    fn unavailable(status: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            rtt_us: None,
            rtt_variance_us: None,
            send_congestion_window_segments: None,
            local_sender_total_retransmissions: None,
            remote_sender_retransmissions: None,
        }
    }
}
pub fn decode_linux(bytes: &[u8]) -> TcpStats {
    let field = |offset| {
        bytes
            .get(offset..offset + 4)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_ne_bytes)
    };
    TcpStats {
        status: if bytes.len() >= 104 {
            "available"
        } else {
            "partial"
        }
        .into(),
        rtt_us: field(68),
        rtt_variance_us: field(72),
        send_congestion_window_segments: field(80),
        local_sender_total_retransmissions: field(100),
        remote_sender_retransmissions: None,
    }
}
pub fn sample(stream: &tokio::net::TcpStream) -> TcpStats {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut bytes = [0u8; 256];
        let mut length = bytes.len() as libc::socklen_t;
        // SAFETY: live borrowed socket, writable initialized buffer, exact capacity;
        // getsockopt updates length and does not retain either pointer.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if rc < 0 {
            return TcpStats::unavailable(format!(
                "unavailable: {}",
                std::io::Error::last_os_error()
            ));
        }
        decode_linux(&bytes[..(length as usize).min(bytes.len())])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        TcpStats::unavailable("unsupported_platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn respects_kernel_length() {
        let mut bytes = [0; 104];
        bytes[68..72].copy_from_slice(&1234u32.to_ne_bytes());
        for length in 0..104 {
            assert_eq!(
                decode_linux(&bytes[..length]).local_sender_total_retransmissions,
                None
            );
        }
        let stats = decode_linux(&bytes);
        assert_eq!(stats.rtt_us, Some(1234));
        assert_eq!(stats.local_sender_total_retransmissions, Some(0));
        assert_eq!(stats.remote_sender_retransmissions, None);
    }
}
