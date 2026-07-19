use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};

use crate::{OutletConfig, OutletKind, UdpCapabilityEvidence, UdpCapabilityStatus};

pub const UDP_EVIDENCE_VERSION: u32 = 1;
pub const UDP_MODEL_VERSION: u32 = 1;
pub const UDP_PROBE_VERSION: &str = "socks5-udp-associate-v1";

#[derive(Debug, Clone)]
pub struct UdpProbeTarget {
    pub address: SocketAddr,
    pub request: Vec<u8>,
    pub expected_response: Vec<u8>,
}

/// Classifies a subscription only from provider readiness plus at least two
/// independent controlled end-to-end UDP outcomes. Mixed or insufficient
/// evidence remains unknown rather than over-promising support.
#[must_use]
pub fn classify_subscription_udp(
    outlet: &OutletConfig,
    provider_ready: bool,
    controlled_outcomes: &[bool],
) -> UdpCapabilityEvidence {
    if !provider_ready {
        return unknown_udp_evidence(outlet, "subscription_provider_not_ready");
    }
    if controlled_outcomes.len() < 2 {
        return unknown_udp_evidence(outlet, "subscription_cross_validation_required");
    }
    if controlled_outcomes.iter().all(|result| *result) {
        return evidence(
            outlet,
            UdpCapabilityStatus::Supported,
            "subscription_udp_cross_validation_succeeded",
        );
    }
    if controlled_outcomes.iter().all(|result| !*result) {
        return evidence(
            outlet,
            UdpCapabilityStatus::TcpOnly,
            "subscription_udp_cross_validation_failed",
        );
    }
    unknown_udp_evidence(outlet, "subscription_udp_evidence_conflicted")
}

#[must_use]
pub fn unknown_udp_evidence(outlet: &OutletConfig, reason_code: &str) -> UdpCapabilityEvidence {
    evidence(outlet, UdpCapabilityStatus::Unknown, reason_code)
}

#[must_use]
pub fn is_current_udp_evidence(outlet: &OutletConfig, evidence: &UdpCapabilityEvidence) -> bool {
    let (fingerprint, generation) = outlet_udp_configuration(outlet);
    evidence.outlet_id == outlet.id
        && evidence.evidence_version == UDP_EVIDENCE_VERSION
        && evidence.probe_version == UDP_PROBE_VERSION
        && evidence.model_version == UDP_MODEL_VERSION
        && evidence.configuration_fingerprint == fingerprint
        && evidence.configuration_generation == generation
}

#[must_use]
pub fn current_udp_status(
    outlet: &OutletConfig,
    evidence: Option<&UdpCapabilityEvidence>,
) -> UdpCapabilityStatus {
    evidence
        .filter(|item| is_current_udp_evidence(outlet, item))
        .map_or(UdpCapabilityStatus::Unknown, |item| item.status)
}

#[must_use]
pub fn outlet_udp_configuration(outlet: &OutletConfig) -> (String, u64) {
    let encoded = serde_json::to_vec(outlet).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    let fingerprint = digest
        .iter()
        .fold(String::with_capacity(64), |mut value, byte| {
            let _ = write!(value, "{byte:02x}");
            value
        });
    let generation = digest
        .iter()
        .take(8)
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    (fingerprint, generation)
}

#[must_use]
pub fn probe_local_proxy_udp(
    outlet: &OutletConfig,
    targets: &[UdpProbeTarget],
    timeout: Duration,
) -> UdpCapabilityEvidence {
    let OutletKind::LocalProxy { endpoint } = &outlet.kind else {
        return unknown_udp_evidence(outlet, "subscription_end_to_end_probe_required");
    };
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return unknown_udp_evidence(outlet, "invalid_local_proxy_endpoint");
    };
    if url.scheme() == "http" {
        return evidence(
            outlet,
            UdpCapabilityStatus::TcpOnly,
            "http_proxy_transport_has_no_udp",
        );
    }
    let Some(host) = url.host_str() else {
        return unknown_udp_evidence(outlet, "invalid_local_proxy_endpoint");
    };
    let Ok(ip) = host.parse::<IpAddr>() else {
        return unknown_udp_evidence(outlet, "invalid_local_proxy_endpoint");
    };
    if !ip.is_loopback() {
        return unknown_udp_evidence(outlet, "non_loopback_proxy_rejected");
    }
    let Some(port) = url.port() else {
        return unknown_udp_evidence(outlet, "invalid_local_proxy_endpoint");
    };
    if targets.is_empty() {
        return unknown_udp_evidence(outlet, "controlled_udp_target_unavailable");
    }
    if targets
        .iter()
        .any(|target| !target.address.ip().is_loopback())
    {
        return unknown_udp_evidence(outlet, "non_loopback_udp_target_rejected");
    }

    match probe_authorized_socks5_udp(SocketAddr::new(ip, port), targets, timeout) {
        Ok(outcomes) if outcomes.iter().any(|result| *result) => evidence(
            outlet,
            UdpCapabilityStatus::Supported,
            "controlled_udp_echo_succeeded",
        ),
        Ok(_) => unknown_udp_evidence(outlet, "controlled_udp_echo_failed"),
        Err(UdpProbeError::Unsupported) => evidence(
            outlet,
            UdpCapabilityStatus::TcpOnly,
            "socks5_udp_associate_rejected",
        ),
        Err(UdpProbeError::Unavailable) => unknown_udp_evidence(outlet, "local_proxy_unavailable"),
        Err(UdpProbeError::InvalidResponse) => {
            unknown_udp_evidence(outlet, "socks5_udp_response_invalid")
        }
    }
}

fn evidence(
    outlet: &OutletConfig,
    status: UdpCapabilityStatus,
    reason_code: &str,
) -> UdpCapabilityEvidence {
    let (configuration_fingerprint, configuration_generation) = outlet_udp_configuration(outlet);
    UdpCapabilityEvidence {
        outlet_id: outlet.id.clone(),
        status,
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        evidence_version: UDP_EVIDENCE_VERSION,
        probe_version: UDP_PROBE_VERSION.into(),
        model_version: UDP_MODEL_VERSION,
        configuration_fingerprint,
        configuration_generation,
        reason_code: reason_code.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpProbeError {
    Unsupported,
    Unavailable,
    InvalidResponse,
}

/// Executes SOCKS5 UDP ASSOCIATE against caller-authorized targets and returns
/// one result per target. Targets and packets are never persisted or logged.
///
/// # Errors
///
/// Returns only a sanitized protocol/availability classification.
pub fn probe_authorized_socks5_udp(
    proxy: SocketAddr,
    targets: &[UdpProbeTarget],
    timeout: Duration,
) -> Result<Vec<bool>, UdpProbeError> {
    let mut control =
        TcpStream::connect_timeout(&proxy, timeout).map_err(|_| UdpProbeError::Unavailable)?;
    control
        .set_read_timeout(Some(timeout))
        .map_err(|_| UdpProbeError::Unavailable)?;
    control
        .set_write_timeout(Some(timeout))
        .map_err(|_| UdpProbeError::Unavailable)?;
    control
        .write_all(&[5, 1, 0])
        .map_err(|_| UdpProbeError::Unavailable)?;
    let mut greeting = [0_u8; 2];
    control
        .read_exact(&mut greeting)
        .map_err(|_| UdpProbeError::Unavailable)?;
    if greeting != [5, 0] {
        return Err(UdpProbeError::InvalidResponse);
    }
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(|_| UdpProbeError::Unavailable)?;
    let relay = read_socks5_reply(&mut control)?;
    if !relay.ip().is_loopback() {
        return Err(UdpProbeError::InvalidResponse);
    }
    let bind_ip = if relay.is_ipv6() {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    let socket =
        UdpSocket::bind(SocketAddr::new(bind_ip, 0)).map_err(|_| UdpProbeError::Unavailable)?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| UdpProbeError::Unavailable)?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|_| UdpProbeError::Unavailable)?;

    let mut outcomes = Vec::with_capacity(targets.len());
    for target in targets {
        let packet = encode_udp_request(target.address, &target.request);
        if socket.send_to(&packet, relay).is_err() {
            outcomes.push(false);
            continue;
        }
        let mut response = vec![0_u8; 65_535].into_boxed_slice();
        let Ok((length, _)) = socket.recv_from(&mut response) else {
            outcomes.push(false);
            continue;
        };
        outcomes.push(
            decode_udp_response(&response[..length])
                .is_some_and(|payload| payload == target.expected_response),
        );
    }
    Ok(outcomes)
}

fn read_socks5_reply(stream: &mut TcpStream) -> Result<SocketAddr, UdpProbeError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| UdpProbeError::Unavailable)?;
    if header[0] != 5 {
        return Err(UdpProbeError::InvalidResponse);
    }
    if header[1] != 0 {
        return if header[1] == 7 {
            Err(UdpProbeError::Unsupported)
        } else {
            Err(UdpProbeError::Unavailable)
        };
    }
    let ip = match header[3] {
        1 => {
            let mut bytes = [0_u8; 4];
            stream
                .read_exact(&mut bytes)
                .map_err(|_| UdpProbeError::InvalidResponse)?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        4 => {
            let mut bytes = [0_u8; 16];
            stream
                .read_exact(&mut bytes)
                .map_err(|_| UdpProbeError::InvalidResponse)?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return Err(UdpProbeError::InvalidResponse),
    };
    let mut port = [0_u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|_| UdpProbeError::InvalidResponse)?;
    let address = SocketAddr::new(ip, u16::from_be_bytes(port));
    if address.ip().is_unspecified() {
        Ok(SocketAddr::new(
            if address.is_ipv6() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            },
            address.port(),
        ))
    } else {
        Ok(address)
    }
}

fn encode_udp_request(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match target.ip() {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn decode_udp_response(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return None;
    }
    let address_length = match packet[3] {
        1 => 4,
        4 => 16,
        _ => return None,
    };
    packet.get(4 + address_length + 2..)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    fn local(endpoint: &str) -> OutletConfig {
        OutletConfig {
            id: "local-test".into(),
            label: "Local test".into(),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: endpoint.into(),
            },
        }
    }

    fn scripted_socks_result(
        greeting_reply: [u8; 2],
        reply_code: Option<u8>,
    ) -> UdpCapabilityEvidence {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("address").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&greeting_reply).expect("method");
            if let Some(reply_code) = reply_code {
                let mut associate = [0_u8; 10];
                stream.read_exact(&mut associate).expect("associate");
                assert_eq!(associate[1], 3);
                stream
                    .write_all(&[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0])
                    .expect("reply");
            }
        });
        let target = UdpProbeTarget {
            address: "127.0.0.1:49153".parse().expect("target"),
            request: b"nonce".to_vec(),
            expected_response: b"nonce".to_vec(),
        };
        let result = probe_local_proxy_udp(
            &local(&format!("socks5://127.0.0.1:{port}")),
            &[target],
            Duration::from_millis(100),
        );
        server.join().expect("server");
        result
    }

    #[test]
    fn http_proxy_is_explicitly_tcp_only_without_network_io() {
        let result = probe_local_proxy_udp(
            &local("http://127.0.0.1:49152"),
            &[],
            Duration::from_millis(10),
        );
        assert_eq!(result.status, UdpCapabilityStatus::TcpOnly);
        assert_eq!(result.reason_code, "http_proxy_transport_has_no_udp");
    }

    #[test]
    fn unreachable_socks_proxy_remains_unknown_and_does_not_claim_tcp_down() {
        let target = UdpProbeTarget {
            address: "127.0.0.1:49153".parse().expect("address"),
            request: b"nonce".to_vec(),
            expected_response: b"nonce".to_vec(),
        };
        let result = probe_local_proxy_udp(
            &local("socks5://127.0.0.1:49152"),
            &[target],
            Duration::from_millis(10),
        );
        assert_eq!(result.status, UdpCapabilityStatus::Unknown);
        assert_eq!(result.reason_code, "local_proxy_unavailable");
    }

    #[test]
    fn remote_udp_targets_are_rejected_before_contacting_the_proxy() {
        let target = UdpProbeTarget {
            address: "192.0.2.1:53".parse().expect("address"),
            request: b"nonce".to_vec(),
            expected_response: b"nonce".to_vec(),
        };
        let result = probe_local_proxy_udp(
            &local("socks5://127.0.0.1:49152"),
            &[target],
            Duration::from_millis(10),
        );
        assert_eq!(result.status, UdpCapabilityStatus::Unknown);
        assert_eq!(result.reason_code, "non_loopback_udp_target_rejected");
    }

    #[test]
    fn explicit_socks5_udp_associate_rejection_is_tcp_only() {
        let result = scripted_socks_result([5, 0], Some(7));
        assert_eq!(result.status, UdpCapabilityStatus::TcpOnly);
        assert_eq!(result.reason_code, "socks5_udp_associate_rejected");
    }

    #[test]
    fn all_other_socks5_reply_codes_remain_unknown() {
        for reply_code in [1, 2, 3, 4, 5, 6, 8] {
            let result = scripted_socks_result([5, 0], Some(reply_code));
            assert_eq!(
                result.status,
                UdpCapabilityStatus::Unknown,
                "REP={reply_code:#04x} must not claim TCP-only"
            );
        }
    }

    #[test]
    fn rejected_authentication_and_malformed_version_remain_unknown() {
        for greeting in [[5, 0xff], [4, 0]] {
            let result = scripted_socks_result(greeting, None);
            assert_eq!(result.status, UdpCapabilityStatus::Unknown);
            assert_eq!(result.reason_code, "socks5_udp_response_invalid");
        }
    }

    #[test]
    fn subscription_requires_separate_end_to_end_evidence() {
        let outlet = OutletConfig {
            id: "sub-test".into(),
            label: "Subscription".into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: "secret.test".into(),
                provider_update_seconds: 180,
            },
        };
        let result = probe_local_proxy_udp(&outlet, &[], Duration::from_millis(10));
        assert_eq!(result.status, UdpCapabilityStatus::Unknown);
        assert_eq!(result.reason_code, "subscription_end_to_end_probe_required");
    }

    #[test]
    fn subscription_requires_provider_and_cross_validated_end_to_end_results() {
        let outlet = OutletConfig {
            id: "sub".into(),
            label: "Subscription".into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: "secret.sub".into(),
                provider_update_seconds: 180,
            },
        };
        assert_eq!(
            classify_subscription_udp(&outlet, false, &[true, true]).status,
            UdpCapabilityStatus::Unknown
        );
        assert_eq!(
            classify_subscription_udp(&outlet, true, &[true]).status,
            UdpCapabilityStatus::Unknown
        );
        assert_eq!(
            classify_subscription_udp(&outlet, true, &[true, true]).status,
            UdpCapabilityStatus::Supported
        );
        assert_eq!(
            classify_subscription_udp(&outlet, true, &[false, false]).status,
            UdpCapabilityStatus::TcpOnly
        );
        assert_eq!(
            classify_subscription_udp(&outlet, true, &[true, false]).status,
            UdpCapabilityStatus::Unknown
        );
    }

    #[test]
    fn evidence_versions_and_outlet_configuration_are_validated_centrally() {
        let outlet = local("socks5://127.0.0.1:49152");
        let mut evidence = unknown_udp_evidence(&outlet, "test");
        evidence.status = UdpCapabilityStatus::Supported;
        assert!(is_current_udp_evidence(&outlet, &evidence));
        assert_eq!(
            current_udp_status(&outlet, Some(&evidence)),
            UdpCapabilityStatus::Supported
        );

        for mutate in [
            |item: &mut UdpCapabilityEvidence| item.evidence_version += 1,
            |item: &mut UdpCapabilityEvidence| item.probe_version.push_str("-stale"),
            |item: &mut UdpCapabilityEvidence| item.model_version += 1,
            |item: &mut UdpCapabilityEvidence| item.configuration_fingerprint.push('0'),
            |item: &mut UdpCapabilityEvidence| item.configuration_generation += 1,
        ] {
            let mut stale = evidence.clone();
            mutate(&mut stale);
            assert_eq!(
                current_udp_status(&outlet, Some(&stale)),
                UdpCapabilityStatus::Unknown
            );
        }

        let changed = local("socks5://127.0.0.1:49153");
        assert_eq!(
            current_udp_status(&changed, Some(&evidence)),
            UdpCapabilityStatus::Unknown
        );
    }
}
