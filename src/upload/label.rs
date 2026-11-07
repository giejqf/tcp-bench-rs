//! Compact evidence labels for the hosted CSV renderer, not route classifications.
use crate::{
    enrichment::remote::Status,
    packet::Protocol,
    probe::ProbeStatus,
    report::{Measurement, NodeReport, Report},
};

pub(super) enum Scope {
    /// A SYN measurement may only borrow observations from a matching TCP trace.
    Syn {
        packet_size: usize,
    },
    RouteOnly,
    DestinationOnly,
}

pub(super) fn render(report: &Report, row: &NodeReport, scope: Scope) -> String {
    let asn = |ip| {
        report
            .enrichment
            .get(&ip)
            .and_then(|data| data.asn)
            .filter(|asn| *asn != 0)
    };
    let trace = row
        .traces
        .iter()
        .filter_map(|measurement| match measurement {
            Measurement::Complete { data } if data.direction == "outward" => Some(data),
            _ => None,
        })
        .filter(|trace| match scope {
            Scope::Syn { packet_size } => {
                trace.protocol == Protocol::Tcp
                    && trace.packet_size == packet_size
                    && trace.initial_port == row.node.primary.port
            }
            Scope::RouteOnly => true,
            Scope::DestinationOnly => false,
        });
    // Prefer TCP, then UDP, then ICMP. Within a protocol show the known ASN at
    // the greatest observed hop limit. This is one observation, not an AS path.
    let observed = trace
        .flat_map(|trace| {
            let protocol = match trace.protocol {
                Protocol::Tcp => 0,
                Protocol::Udp => 1,
                Protocol::Icmp => 2,
            };
            trace.hops.iter().flat_map(move |hop| {
                hop.probes.iter().filter_map(move |probe| {
                    if probe.status != ProbeStatus::Reply {
                        return None;
                    }
                    let ip = probe.responder?;
                    if ip.is_ipv4() != row.node.primary.ip.is_ipv4() {
                        return None;
                    }
                    Some(((protocol, std::cmp::Reverse(hop.hop_limit)), asn(ip)?))
                })
            })
        })
        .min_by_key(|(key, _)| *key);
    if let Some((_, asn)) = observed {
        return format!("out AS{asn}");
    }
    if let Some(asn) = asn(row.node.primary.ip) {
        return format!("dst AS{asn}");
    }

    // Hidden and NoData are converted to "failed" by the hosted renderer.
    // Preserve a useful missing-data reason without fabricating a measurement.
    match report
        .enrichment_lookups
        .get(&row.node.primary.ip)
        .map(|lookup| &lookup.status)
    {
        Some(Status::Timeout) => "ASN timeout",
        Some(Status::RequestLimit | Status::RateLimited) => "ASN limited",
        Some(Status::Unauthorized) => "ASN denied",
        Some(Status::Cancelled) => "ASN cancelled",
        Some(Status::NotFound) => "ASN unknown",
        Some(Status::Error) => "ASN error",
        Some(Status::SkippedNonpublic) => "N/A",
        _ => "ASN unavailable",
    }
    .into()
}
