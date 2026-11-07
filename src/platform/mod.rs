#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{CaptureSocket, RawSocket};

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use crate::{Error, Result, packet::ProbePacket};
    use std::net::IpAddr;
    pub struct RawSocket;
    pub struct CaptureSocket;
    impl CaptureSocket {
        pub fn new(_source: IpAddr, _source_port: u16) -> Result<Self> {
            Err(Error::Unsupported("Linux packet sockets".into()))
        }
        pub async fn receive(&self, _buffer: &mut [u8]) -> Result<(usize, bool)> {
            Err(Error::Unsupported("Linux packet sockets".into()))
        }
    }
    impl RawSocket {
        pub fn new(_source: IpAddr, _protocol: u8) -> Result<Self> {
            Err(Error::Unsupported(
                "raw probes require Linux; discovery and HTTP/TLS work on this platform".into(),
            ))
        }
        pub async fn send(
            &self,
            _packet: &ProbePacket,
            _bytes: &[u8],
        ) -> Result<tokio::time::Instant> {
            Err(Error::Unsupported("Linux raw sockets".into()))
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use unsupported::{CaptureSocket, RawSocket};

pub fn check_capabilities(v6: bool, protocol: crate::packet::Protocol) -> crate::Result<()> {
    let source = if v6 {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    let _sender = RawSocket::new(source, protocol.number(v6))?;
    let _capture = CaptureSocket::new(source, 1)?;
    Ok(())
}
