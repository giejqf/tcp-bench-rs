//! Default preset selection; no bundled endpoint or route classification datasets.
use crate::nodes::Node;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Preserve service order within each family/ISP group and interleave groups.
/// Duplicate IP/port pairs are probed once. The selected subset is deterministic.
pub fn select(nodes: Vec<Node>, limit: usize) -> Vec<Node> {
    let mut seen = BTreeSet::new();
    let mut groups: BTreeMap<(u8, String), VecDeque<Node>> = BTreeMap::new();
    for node in nodes {
        if seen.insert((node.primary.ip, node.primary.port)) {
            groups
                .entry((node.family, node.isp.clone()))
                .or_default()
                .push_back(node);
        }
    }
    let mut selected = Vec::new();
    loop {
        let before = selected.len();
        for group in groups.values_mut() {
            if selected.len() == limit {
                return selected;
            }
            if let Some(node) = group.pop_front() {
                selected.push(node);
            }
        }
        if selected.len() == before {
            return selected;
        }
    }
}

/// UDP connect selects a kernel route without sending any packet.
pub async fn route_available(ip: std::net::IpAddr) -> std::io::Result<()> {
    let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    socket.connect(std::net::SocketAddr::new(ip, 9)).await?;
    if socket.local_addr()?.ip().is_unspecified() {
        return Err(std::io::Error::other(
            "kernel did not select a source address",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_interleaves_groups_and_deduplicates() {
        let input=b"cdn\t4\ta\tOne\t\t192.0.2.1\t443\t\ncdn\t4\tb\tOne\t\t192.0.2.2\t443\t\ncdn\t4\ta\tTwo\t\t192.0.2.3\t443\t\ncdn\t6\ta\tOne\t\t2001:db8::1\t443\t\ncdn\t4\ta\tOne\t\t192.0.2.1\t443\t\n";
        let nodes = crate::nodes::parse_tsv(input).unwrap();
        let selected = select(nodes.clone(), 3);
        assert_eq!(
            selected
                .iter()
                .map(|n| n.primary.ip.to_string())
                .collect::<Vec<_>>(),
            ["192.0.2.1", "192.0.2.3", "2001:db8::1"]
        );
        assert_eq!(select(nodes.clone(), 20).len(), 4);
        assert!(select(nodes, 0).is_empty());
    }
}
