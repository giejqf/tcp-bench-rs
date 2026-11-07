use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_NODE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_NODES: usize = 4096;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub ip: IpAddr,
    pub port: u16,
    pub target: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub kind: String,
    pub family: u8,
    pub province: String,
    pub isp: String,
    pub primary: Target,
    pub backup: Option<Target>,
    /// Service supplied a backup name but no address; never resolved or used implicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_backup: Option<UnresolvedBackup>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedBackup {
    pub host: String,
    pub port: u16,
    pub target: String,
}

pub fn validate_ip(ip: IpAddr) -> Result<IpAddr> {
    if ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
        || matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some())
    {
        return Err(Error::Nodes(format!(
            "{ip}: unspecified, multicast, broadcast, mapped IPv6 and unscoped link-local IPv6 targets are unsupported"
        )));
    }
    Ok(ip)
}
pub fn parse_tsv(bytes: &[u8]) -> Result<Vec<Node>> {
    if bytes.len() > MAX_NODE_BYTES {
        return Err(Error::Nodes("node response exceeds 2 MiB".into()));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::Nodes(format!("TSV is not UTF-8: {e}")))?
        .trim_start_matches('\u{feff}');
    let mut nodes = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fail = |message: String| Error::Nodes(format!("line {}: {message}", line_number + 1));
        if line.len() > 8192 || line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(fail(
                "invalid control character or record over 8192 bytes".into(),
            ));
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.first() == Some(&"type") {
            if !nodes.is_empty()
                || fields.len() != 12
                || fields[1] != "family"
                || fields[5] != "ip"
                || fields[6] != "port"
            {
                return Err(fail(
                    "invalid or misplaced 12-column getNodes header".into(),
                ));
            }
            continue;
        }
        if fields.len() != 8 && fields.len() != 12 {
            return Err(fail(format!(
                "expected 8 primary or 12 primary+backup TSV columns, found {}",
                fields.len()
            )));
        }
        let kind = fields[0];
        if !matches!(
            kind,
            "cdn"
                | "cernet"
                | "cernet2"
                | "telegram"
                | "tos"
                | "tosutil"
                | "speedtest"
                | "applecdn"
                | "iperf3"
        ) {
            return Err(fail(format!("unknown node type {kind:?}")));
        }
        let family = match fields[1] {
            "4" => 4,
            "6" => 6,
            _ => return Err(fail("family must be 4 or 6".into())),
        };
        if (kind == "cernet" && family != 4) || (kind == "cernet2" && family != 6) {
            return Err(fail(
                "CERNET requires family 4; CERNET2 requires family 6".into(),
            ));
        }
        let target =
            |host: &str, ip: &str, port: &str, path: &str, default_port: u16| -> Result<Target> {
                let ip = ip
                    .parse::<IpAddr>()
                    .map_err(|_| fail(format!("invalid IP address {ip:?}")))?;
                validate_ip(ip).map_err(|e| fail(e.to_string()))?;
                if ip.is_ipv6() != (family == 6) {
                    return Err(fail("IP address does not match family column".into()));
                }
                let port = if port.is_empty() {
                    default_port
                } else {
                    port.parse::<u16>()
                        .ok()
                        .filter(|&p| p != 0)
                        .ok_or_else(|| fail(format!("invalid port {port:?}")))?
                };
                if host.len() > 253 || host.contains(['/', '@', '\\', ' ']) {
                    return Err(fail("invalid host column".into()));
                }
                Ok(Target {
                    host: host.into(),
                    ip,
                    port,
                    target: path.into(),
                })
            };
        // The reference defaults the primary port to 80 for every type.
        let primary = target(fields[4], fields[5], fields[6], fields[7], 80)?;
        let mut unresolved_backup = None;
        let backup = if fields.len() == 12 && fields[8..].iter().any(|f| !f.is_empty()) {
            if fields[9].is_empty() {
                let host = fields[8];
                if host.is_empty() || host.len() > 253 || host.contains(['/', '@', '\\', ' ']) {
                    return Err(fail("unresolved backup requires a valid hostname".into()));
                }
                let port = if fields[10].is_empty() {
                    if matches!(kind, "cernet" | "cernet2") {
                        443
                    } else {
                        80
                    }
                } else {
                    fields[10]
                        .parse::<u16>()
                        .ok()
                        .filter(|&p| p > 0)
                        .ok_or_else(|| fail("invalid unresolved backup port".into()))?
                };
                unresolved_backup = Some(UnresolvedBackup {
                    host: host.into(),
                    port,
                    target: fields[11].into(),
                });
                None
            } else {
                Some(target(
                    fields[8],
                    fields[9],
                    fields[10],
                    fields[11],
                    if matches!(kind, "cernet" | "cernet2") {
                        443
                    } else {
                        80
                    },
                )?)
            }
        } else {
            None
        };
        nodes.push(Node {
            kind: kind.into(),
            family,
            province: fields[2].into(),
            isp: fields[3].into(),
            primary,
            backup,
            unresolved_backup,
        });
        if nodes.len() > MAX_NODES {
            return Err(fail(format!("more than {MAX_NODES} nodes")));
        }
    }
    if nodes.is_empty() {
        return Err(Error::Nodes("no node records found".into()));
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primary_and_backup() {
        let n=parse_tsv(b"cdn\t4\tbj\tExample\texample.test\t192.0.2.1\t443\t/path\tb.test\t192.0.2.2\t8443\t/backup\n").unwrap();
        assert_eq!(n[0].primary.port, 443);
        assert_eq!(n[0].backup.as_ref().unwrap().port, 8443);
    }
    #[test]
    fn accepts_v6_and_empty_fields() {
        let n = parse_tsv(b"cernet2\t6\t\t\t\t2001:db8::1\t\t\n").unwrap();
        assert_eq!(n[0].primary.port, 80);
    }
    #[test]
    fn unresolved_backup_is_preserved_without_inventing_an_address() {
        let nodes = parse_tsv(
            b"cdn\t6\tlab\tTest\tmain.test\t2001:db8::1\t80\t/path\tbackup.test\t\t80\t/backup\n",
        )
        .unwrap();
        assert!(nodes[0].backup.is_none());
        let backup = nodes[0].unresolved_backup.as_ref().unwrap();
        assert_eq!(backup.host, "backup.test");
        assert_eq!(backup.port, 80);
        assert_eq!(backup.target, "/backup");
        assert!(parse_tsv(b"cdn\t6\tlab\tTest\tmain.test\t2001:db8::1\t80\t/path\tbackup.test\t\t0\t/backup\n").is_err());
    }
    #[test]
    fn malformed_nodes_rejected() {
        for record in [
            "cdn\t4\tx\tx\tx\t::1\t80\t/",
            "cdn\t4\tx\tx\tx\t127.0.0.1\t0\t/",
            "cdn\t4\tx\tx\tx\t127.0.0.1\t65536\t/",
            "cdn\t4\tx\tx\tx\t$(id)\t80\t/",
            "cdn\t4\tx\tx\tx\t224.0.0.1\t80\t/",
            "unknown\t4\tx\tx\tx\t127.0.0.1\t80\t/",
        ] {
            assert!(parse_tsv(record.as_bytes()).is_err(), "{record}");
        }
    }
}
