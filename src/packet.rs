//! Stateless network codecs. Sizes are complete IP datagram sizes, without Ethernet.
use crate::{Error, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}
impl Protocol {
    pub fn number(self, v6: bool) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp if v6 => 58,
            Self::Icmp => 1,
        }
    }
    pub fn minimum_size(self, v6: bool) -> usize {
        (if v6 { 40 } else { 20 }) + if self == Self::Tcp { 20 } else { 8 }
    }
}

#[derive(Clone, Debug)]
pub struct ProbePacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub token: u32,
    pub protocol: Protocol,
    pub hop_limit: u8,
    pub size: usize,
}

fn word_sum(bytes: &[u8]) -> u64 {
    bytes
        .chunks(2)
        .map(|pair| ((pair[0] as u64) << 8) | pair.get(1).copied().unwrap_or(0) as u64)
        .sum()
}
fn finish_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
pub fn checksum(bytes: &[u8]) -> u16 {
    finish_checksum(word_sum(bytes))
}

/// No payload copy or allocation in the checksum path.
pub fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, data: &[u8]) -> u16 {
    let mut pseudo = [0u8; 40];
    let header = match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo[..4].copy_from_slice(&s.octets());
            pseudo[4..8].copy_from_slice(&d.octets());
            pseudo[9] = protocol;
            pseudo[10..12].copy_from_slice(&(data.len() as u16).to_be_bytes());
            12
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo[..16].copy_from_slice(&s.octets());
            pseudo[16..32].copy_from_slice(&d.octets());
            pseudo[32..36].copy_from_slice(&(data.len() as u32).to_be_bytes());
            pseudo[39] = protocol;
            40
        }
        _ => return 1,
    };
    finish_checksum(word_sum(&pseudo[..header]) + word_sum(data))
}

impl ProbePacket {
    pub fn actual_size(&self) -> usize {
        self.size
            .max(self.protocol.minimum_size(self.source.is_ipv6()))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.source.is_ipv6() != self.destination.is_ipv6()
            || self.hop_limit == 0
            || self.actual_size() > 65535
            || self.destination_port == 0
            || self.source_port == 0
        {
            return Err(Error::Config(
                "invalid packet addresses, size, port, or hop limit".into(),
            ));
        }
        let v6 = self.source.is_ipv6();
        let ip_len = if v6 { 40 } else { 20 };
        let mut data = vec![0; self.actual_size()];
        let length = data.len();
        let proto = self.protocol.number(v6);
        match (self.source, self.destination) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                data[0] = 0x45;
                data[2..4].copy_from_slice(&(length as u16).to_be_bytes());
                data[4..6].copy_from_slice(&(self.token as u16).to_be_bytes());
                data[6] = 0x40; // DF: a large probe must not silently become fragments.
                data[8] = self.hop_limit;
                data[9] = proto;
                data[12..16].copy_from_slice(&s.octets());
                data[16..20].copy_from_slice(&d.octets());
                let sum = checksum(&data[..20]);
                data[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                data[0] = 0x60;
                data[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
                data[6] = proto;
                data[7] = self.hop_limit;
                data[8..24].copy_from_slice(&s.octets());
                data[24..40].copy_from_slice(&d.octets());
            }
            _ => unreachable!("validated matching address families"),
        }
        let segment = &mut data[ip_len..];
        let header = if self.protocol == Protocol::Tcp {
            20
        } else {
            8
        };
        for (index, byte) in segment[header..].iter_mut().enumerate() {
            *byte = self.token.to_be_bytes()[index % 4];
        }
        let check_offset = match self.protocol {
            Protocol::Tcp => {
                segment[..2].copy_from_slice(&self.source_port.to_be_bytes());
                segment[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
                segment[4..8].copy_from_slice(&self.token.to_be_bytes());
                segment[12] = 0x50;
                segment[13] = 0x02;
                segment[14..16].copy_from_slice(&64240u16.to_be_bytes());
                16
            }
            Protocol::Udp => {
                let len = segment.len() as u16;
                segment[..2].copy_from_slice(&self.source_port.to_be_bytes());
                segment[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
                segment[4..6].copy_from_slice(&len.to_be_bytes());
                6
            }
            Protocol::Icmp => {
                segment[0] = if v6 { 128 } else { 8 };
                segment[4..8].copy_from_slice(&self.token.to_be_bytes());
                2
            }
        };
        let mut sum = if self.protocol == Protocol::Icmp && !v6 {
            checksum(segment)
        } else {
            transport_checksum(self.source, self.destination, proto, segment)
        };
        if self.protocol == Protocol::Udp && sum == 0 {
            sum = 0xffff;
        }
        segment[check_offset..check_offset + 2].copy_from_slice(&sum.to_be_bytes());
        Ok(data)
    }
}

#[derive(Debug)]
pub struct Datagram<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// Quotes may omit the tail, but must contain every header they describe.
pub fn decode_ip(data: &[u8], quoted: bool) -> Option<Datagram<'_>> {
    match data.first()? >> 4 {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let header = (data[0] as usize & 15) * 4;
            let total = u16::from_be_bytes([data[2], data[3]]) as usize;
            if header < 20
                || total < header
                || data.len() < header
                || (!quoted && total > data.len())
                || u16::from_be_bytes([data[6], data[7]]) & 0x3fff != 0
                || checksum(&data[..header]) != 0
            {
                return None;
            }
            Some(Datagram {
                source: Ipv4Addr::new(data[12], data[13], data[14], data[15]).into(),
                destination: Ipv4Addr::new(data[16], data[17], data[18], data[19]).into(),
                protocol: data[9],
                payload: &data[header..total.min(data.len())],
            })
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let total = 40 + u16::from_be_bytes([data[4], data[5]]) as usize;
            if (!quoted && total > data.len()) || total == 40 {
                return None;
            }
            let data = &data[..total.min(data.len())];
            let mut next = data[6];
            let mut offset = 40;
            for _ in 0..8 {
                if !matches!(next, 0 | 43 | 60 | 44 | 51) {
                    break;
                }
                let head = data.get(offset..offset + 2)?;
                let length = match next {
                    44 => {
                        // Only atomic fragments; no reassembly in the codec.
                        if u16::from_be_bytes(data.get(offset + 2..offset + 4)?.try_into().ok()?)
                            != 0
                        {
                            return None;
                        }
                        8
                    }
                    51 => (head[1] as usize + 2) * 4,
                    _ => (head[1] as usize + 1) * 8,
                };
                next = head[0];
                offset += length;
                if offset > data.len() {
                    return None;
                }
            }
            if matches!(next, 0 | 43 | 60 | 44 | 51) {
                return None;
            }
            Some(Datagram {
                source: Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?).into(),
                destination: Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?).into(),
                protocol: next,
                payload: &data[offset..],
            })
        }
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ReplyKind {
    SynAck,
    Reset,
    EchoReply,
    TimeExceeded,
    Unreachable { code: u8 },
    PacketTooBig { mtu: u32 },
    ParameterProblem,
}
impl ReplyKind {
    pub fn endpoint_reply(&self) -> bool {
        matches!(self, Self::SynAck | Self::Reset | Self::EchoReply)
    }
}

/// A reply must match addresses, protocol, and probe identity. Invalid checksums are ignored.
pub fn correlate(probe: &ProbePacket, reply: Datagram<'_>) -> Option<ReplyKind> {
    correlate_received(probe, reply, false)
}

/// The platform may attest checksum offload using kernel packet auxiliary data.
/// Never infer offload from the packet's checksum value or IP address.
pub(crate) fn correlate_received(
    probe: &ProbePacket,
    reply: Datagram<'_>,
    checksum_offloaded: bool,
) -> Option<ReplyKind> {
    if reply.destination != probe.source || reply.source.is_ipv6() != probe.source.is_ipv6() {
        return None;
    }
    let v6 = probe.source.is_ipv6();
    let p = reply.payload;
    if reply.protocol == 6 && probe.protocol == Protocol::Tcp && reply.source == probe.destination {
        if p.len() < 20
            || p[12] >> 4 < 5
            || (p[12] as usize >> 4) * 4 > p.len()
            || (!checksum_offloaded
                && transport_checksum(reply.source, reply.destination, 6, p) != 0)
            || p[..2] != probe.destination_port.to_be_bytes()
            || p[2..4] != probe.source_port.to_be_bytes()
        {
            return None;
        }
        let ack = u32::from_be_bytes(p[8..12].try_into().ok()?);
        let syn_end = probe.token.wrapping_add(1);
        let data_end =
            syn_end.wrapping_add((probe.actual_size() - probe.protocol.minimum_size(v6)) as u32);
        if p[13] & 0x10 == 0 || (ack != syn_end && ack != data_end) {
            return None;
        }
        return match p[13] & 0x17 {
            0x12 => Some(ReplyKind::SynAck),
            0x14 => Some(ReplyKind::Reset),
            _ => None,
        };
    }
    if reply.protocol != if v6 { 58 } else { 1 } || p.len() < 8 {
        return None;
    }
    let valid = if v6 {
        transport_checksum(reply.source, reply.destination, 58, p) == 0
    } else {
        checksum(p) == 0
    };
    if !valid && !checksum_offloaded {
        return None;
    }
    if probe.protocol == Protocol::Icmp
        && reply.source == probe.destination
        && p[0] == if v6 { 129 } else { 0 }
        && p[1] == 0
    {
        let original = probe.encode().ok()?;
        let off = if v6 { 40 } else { 20 };
        return (p[4..] == original[off + 4..]).then_some(ReplyKind::EchoReply);
    }
    let kind = match (v6, p[0], p[1]) {
        (false, 11, 0) | (true, 3, 0) => ReplyKind::TimeExceeded,
        (false, 3, 4) => ReplyKind::PacketTooBig {
            mtu: u16::from_be_bytes([p[6], p[7]]) as u32,
        },
        (false, 3, code) | (true, 1, code) => ReplyKind::Unreachable { code },
        (true, 2, 0) => ReplyKind::PacketTooBig {
            mtu: u32::from_be_bytes(p[4..8].try_into().ok()?),
        },
        (false, 12, _) | (true, 4, _) => ReplyKind::ParameterProblem,
        _ => return None,
    };
    let quoted = decode_ip(&p[8..], true)?;
    if quoted.source != probe.source
        || quoted.destination != probe.destination
        || quoted.protocol != probe.protocol.number(v6)
        || quoted.payload.len() < 8
    {
        return None;
    }
    let original = probe.encode().ok()?;
    let offset = if v6 { 40 } else { 20 };
    // TCP's first eight bytes contain both ports and the 32-bit sequence. UDP's
    // include length and checksum; its destination port changes for each hop probe.
    (quoted.payload[..8] == original[offset..offset + 8]).then_some(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn probe(v6: bool, protocol: Protocol) -> ProbePacket {
        ProbePacket {
            source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if v6 { "2001:db8::2" } else { "198.51.100.2" }
                .parse()
                .unwrap(),
            source_port: 41000,
            destination_port: 443,
            token: 0xffff_fffe,
            protocol,
            hop_limit: 12,
            size: 0,
        }
    }
    #[test]
    fn known_checksum() {
        assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        assert_eq!(checksum(&[1]), 0xfeff);
    }
    #[test]
    fn golden_ipv4_syn() {
        // Independent fixture: RFC header fields, checked with a separate integer-sum encoder.
        let expected =
            "45000028fffe40000c06829ac0000201c6336402a02801bbfffffffe000000005002faf026d80000";
        let actual = probe(false, Protocol::Tcp)
            .encode()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected);
    }
    #[test]
    fn extension_headers_and_fragments() {
        let base = probe(true, Protocol::Udp).encode().unwrap();
        let mut extended = base[..40].to_vec();
        extended[6] = 60;
        extended.extend([17, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend(&base[40..]);
        extended[4..6].copy_from_slice(&16u16.to_be_bytes());
        let packet = decode_ip(&extended, false).unwrap();
        assert_eq!(packet.protocol, 17);
        assert_eq!(packet.payload, &base[40..]);
        extended[41] = 255;
        assert!(decode_ip(&extended, false).is_none());
        extended[6] = 44;
        extended[41] = 0;
        extended[43] = 1;
        assert!(decode_ip(&extended, false).is_none());
        let mut v4 = probe(false, Protocol::Tcp).encode().unwrap();
        v4[6] = 0x20;
        v4[10..12].fill(0);
        let sum = checksum(&v4[..20]);
        v4[10..12].copy_from_slice(&sum.to_be_bytes());
        assert!(decode_ip(&v4, false).is_none());
    }
    #[test]
    fn malformed_input_sweep_is_panic_free() {
        let mut seed = 123456789u32;
        for length in 0..512 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (seed >> 24) as u8;
            }
            for quoted in [false, true] {
                let _ = decode_ip(&bytes, quoted);
            }
            for v6 in [false, true] {
                let request = probe(v6, Protocol::Tcp);
                let _ = correlate(
                    &request,
                    Datagram {
                        source: request.destination,
                        destination: request.source,
                        protocol: 6,
                        payload: &bytes,
                    },
                );
            }
        }
    }
    #[test]
    fn encode_families_and_sizes() {
        for v6 in [false, true] {
            for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
                for size in [0, 1, 99, 1500] {
                    let mut probe = probe(v6, proto);
                    probe.size = size;
                    let bytes = probe.encode().unwrap();
                    let ip = decode_ip(&bytes, false).unwrap();
                    assert_eq!(bytes.len(), size.max(proto.minimum_size(v6)));
                    assert_eq!(ip.source, probe.source);
                    assert_eq!(ip.destination, probe.destination);
                    assert_eq!(
                        if proto == Protocol::Icmp && !v6 {
                            checksum(ip.payload)
                        } else {
                            transport_checksum(ip.source, ip.destination, ip.protocol, ip.payload)
                        },
                        0
                    );
                }
            }
        }
    }
    #[test]
    fn truncated_and_malformed_packets_never_match() {
        for v6 in [false, true] {
            let bytes = probe(v6, Protocol::Tcp).encode().unwrap();
            for end in 0..bytes.len() {
                assert!(decode_ip(&bytes[..end], false).is_none());
            }
            for length in 0..300 {
                let bytes = vec![0xff; length];
                assert!(decode_ip(&bytes, false).is_none());
            }
        }
    }
    #[test]
    fn syn_ack_correlation_and_wrapping_payload_ack() {
        for v6 in [false, true] {
            let mut request = probe(v6, Protocol::Tcp);
            request.size = 100;
            let mut response = ProbePacket {
                source: request.destination,
                destination: request.source,
                source_port: request.destination_port,
                destination_port: request.source_port,
                ..request.clone()
            }
            .encode()
            .unwrap();
            let offset = if v6 { 40 } else { 20 };
            let p = &mut response[offset..];
            p[8..12].copy_from_slice(&request.token.wrapping_add(1).to_be_bytes());
            p[13] = 0x12;
            p[16..18].fill(0);
            let c = transport_checksum(request.destination, request.source, 6, p);
            p[16..18].copy_from_slice(&c.to_be_bytes());
            assert_eq!(
                correlate(&request, decode_ip(&response, false).unwrap()),
                Some(ReplyKind::SynAck)
            );
            request.token = request.token.wrapping_add(1);
            assert_eq!(
                correlate(&request, decode_ip(&response, false).unwrap()),
                None
            );
        }
    }
    #[test]
    fn minimum_icmp_quotes_match_and_wrong_identity_is_rejected() {
        for v6 in [false, true] {
            for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
                let mut request = probe(v6, protocol);
                let bytes = request.encode().unwrap();
                let offset = if v6 { 40 } else { 20 };
                let mut icmp = vec![0; 8];
                icmp[0] = if v6 { 3 } else { 11 };
                icmp.extend(&bytes[..offset + 8]);
                let source = if v6 { "2001:db8::99" } else { "192.0.2.99" }
                    .parse()
                    .unwrap();
                let sum = if v6 {
                    transport_checksum(source, request.source, 58, &icmp)
                } else {
                    checksum(&icmp)
                };
                icmp[2..4].copy_from_slice(&sum.to_be_bytes());
                let response = || Datagram {
                    source,
                    destination: request.source,
                    protocol: if v6 { 58 } else { 1 },
                    payload: &icmp,
                };
                assert_eq!(
                    correlate(&request, response()),
                    Some(ReplyKind::TimeExceeded)
                );
                request.destination_port += 1;
                if protocol != Protocol::Icmp {
                    assert_eq!(correlate(&request, response()), None);
                }
            }
        }
    }
}
