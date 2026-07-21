use std::time::Duration;
use std::{collections::BTreeMap, path::Path};

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone)]
pub struct ControllerClient {
    client: reqwest::Client,
    base_url: Url,
    secret: String,
}

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("invalid loopback controller address")]
    InvalidAddress,
    #[error("controller request failed")]
    Request,
    #[error("controller returned HTTP {0}")]
    Http(StatusCode),
    #[error("controller response was invalid")]
    Response,
    #[error("selector target is unavailable")]
    TargetUnavailable,
    #[error("selector update could not be confirmed")]
    SelectionUnconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubscriptionNode {
    pub name: String,
    pub proxy_type: String,
    pub alive: Option<bool>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectorNodeSnapshot {
    pub current_node: Option<String>,
    pub nodes: Vec<SubscriptionNode>,
}

#[derive(Debug, Deserialize)]
struct DelayResponse {
    delay: u64,
}

#[derive(Debug, Deserialize)]
struct ProxySelectionResponse {
    now: String,
}

#[derive(Debug, Deserialize)]
struct ProxiesResponse {
    proxies: BTreeMap<String, ProxyApiResponse>,
}

#[derive(Debug, Default, Deserialize)]
struct ProxyApiResponse {
    #[serde(default)]
    now: String,
    #[serde(default)]
    all: Vec<String>,
    #[serde(default, rename = "type")]
    proxy_type: String,
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    history: Vec<DelayHistoryResponse>,
}

#[derive(Debug, Deserialize)]
struct DelayHistoryResponse {
    #[serde(default)]
    delay: u64,
}

#[derive(Debug, Deserialize)]
struct VersionResponse {
    version: String,
}

#[derive(Debug, Serialize)]
struct SelectionRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct ConfigReloadRequest<'a> {
    path: &'a str,
}

impl ControllerClient {
    /// Creates a client for a loopback-only Mihomo controller.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback hosts and invalid URLs.
    pub fn new(address: &str, secret: String, timeout_ms: u64) -> Result<Self, ControllerError> {
        let base_url = Url::parse(address).map_err(|_| ControllerError::InvalidAddress)?;
        let host = base_url.host_str().ok_or(ControllerError::InvalidAddress)?;
        if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Err(ControllerError::InvalidAddress);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|_| ControllerError::Request)?;
        Ok(Self {
            client,
            base_url,
            secret,
        })
    }

    /// Measures one target through a named Mihomo proxy or group.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors.
    pub async fn delay(
        &self,
        proxy_name: &str,
        target: &str,
        timeout_ms: u64,
    ) -> Result<u64, ControllerError> {
        let mut url = self.endpoint(&["proxies", proxy_name, "delay"])?;
        url.query_pairs_mut()
            .append_pair("timeout", &timeout_ms.to_string())
            .append_pair("url", target);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        response
            .json::<DelayResponse>()
            .await
            .map(|body| body.delay)
            .map_err(|_| ControllerError::Response)
    }

    /// Selects a real proxy/group on a Mihomo selector.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport or HTTP errors.
    pub async fn select(&self, selector: &str, target: &str) -> Result<(), ControllerError> {
        let url = self.endpoint(&["proxies", selector])?;
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.secret)
            .json(&SelectionRequest { name: target })
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if response.status().is_success() || response.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(ControllerError::Http(response.status()))
        }
    }

    /// Reads the current member and safe display fields for one selector.
    ///
    /// The response intentionally excludes provider connection parameters.
    /// Node names remain transient and callers must not persist or log them.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors.
    pub async fn selector_nodes(
        &self,
        selector: &str,
    ) -> Result<SelectorNodeSnapshot, ControllerError> {
        let response = self.proxies_response().await?;
        selector_snapshot(selector, &response)
    }

    /// Reads several selector snapshots from one Controller response.
    ///
    /// Missing selectors are omitted so callers can distinguish a reachable
    /// Controller from a provider-backed selector that is not ready yet.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors for the shared
    /// Controller request.
    pub async fn selector_nodes_for(
        &self,
        selectors: &[String],
    ) -> Result<BTreeMap<String, SelectorNodeSnapshot>, ControllerError> {
        let response = self.proxies_response().await?;
        let mut snapshots = BTreeMap::new();
        for selector in selectors {
            if response.proxies.contains_key(selector) {
                snapshots.insert(selector.clone(), selector_snapshot(selector, &response)?);
            }
        }
        Ok(snapshots)
    }

    async fn proxies_response(&self) -> Result<ProxiesResponse, ControllerError> {
        let url = self.endpoint(&["proxies"])?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        response
            .json::<ProxiesResponse>()
            .await
            .map_err(|_| ControllerError::Response)
    }

    /// Selects a member that was present in the selector's latest Controller
    /// snapshot, then reads the authoritative selection back.
    ///
    /// # Errors
    ///
    /// Rejects stale or foreign targets and returns sanitized Controller errors.
    pub async fn select_selector_node(
        &self,
        selector: &str,
        target: &str,
    ) -> Result<SelectorNodeSnapshot, ControllerError> {
        let before = self.selector_nodes(selector).await?;
        if !before.nodes.iter().any(|node| node.name == target) {
            return Err(ControllerError::TargetUnavailable);
        }
        self.select(selector, target)
            .await
            .map_err(|error| match error {
                ControllerError::Request => ControllerError::SelectionUnconfirmed,
                other => other,
            })?;
        let after = self
            .selector_nodes(selector)
            .await
            .map_err(|_| ControllerError::SelectionUnconfirmed)?;
        if after.current_node.as_deref() != Some(target) {
            return Err(ControllerError::SelectionUnconfirmed);
        }
        Ok(after)
    }

    /// Measures a selected proxy-provider member through Mihomo's provider API.
    ///
    /// Provider member names remain internal and are never returned or
    /// persisted. Mihomo exposes provider members through a distinct
    /// healthcheck route rather than the inline-proxy delay route.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors.
    pub async fn delay_selected_provider_member(
        &self,
        group: &str,
        provider: &str,
        target: &str,
        timeout_ms: u64,
    ) -> Result<u64, ControllerError> {
        let url = self.endpoint(&["proxies", group])?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        let member = response
            .json::<ProxySelectionResponse>()
            .await
            .map_err(|_| ControllerError::Response)?
            .now;
        let mut url = self.endpoint(&["providers", "proxies", provider, &member, "healthcheck"])?;
        url.query_pairs_mut()
            .append_pair("timeout", &timeout_ms.to_string())
            .append_pair("url", target);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        response
            .json::<DelayResponse>()
            .await
            .map(|body| body.delay)
            .map_err(|_| ControllerError::Response)
    }

    /// Confirms that the authenticated loopback Controller is a Mihomo API.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors.
    pub async fn is_ready(&self) -> Result<bool, ControllerError> {
        let url = self.endpoint(&["version"])?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        response
            .json::<VersionResponse>()
            .await
            .map(|body| !body.version.trim().is_empty())
            .map_err(|_| ControllerError::Response)
    }

    /// Confirms whether a Mihomo selector currently points to an expected target.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport, HTTP, or response errors.
    pub async fn is_selected(
        &self,
        selector: &str,
        expected: &str,
    ) -> Result<bool, ControllerError> {
        let url = self.endpoint(&["proxies", selector])?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if !response.status().is_success() {
            return Err(ControllerError::Http(response.status()));
        }
        response
            .json::<ProxySelectionResponse>()
            .await
            .map(|body| body.now == expected)
            .map_err(|_| ControllerError::Response)
    }

    /// Requests an immediate refresh of one configured proxy provider.
    ///
    /// # Errors
    ///
    /// Returns sanitized transport or HTTP errors.
    pub async fn update_proxy_provider(&self, provider_name: &str) -> Result<(), ControllerError> {
        let url = self.endpoint(&["providers", "proxies", provider_name])?;
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if response.status().is_success() || response.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(ControllerError::Http(response.status()))
        }
    }

    /// Reloads a configuration file through the authenticated loopback-only
    /// Controller. Callers own the file and must keep it protected.
    ///
    /// # Errors
    ///
    /// Returns a sanitized transport or HTTP error.
    pub async fn reload_config(&self, path: &Path) -> Result<(), ControllerError> {
        let path = path.to_str().ok_or(ControllerError::Request)?;
        let mut url = self.endpoint(&["configs"])?;
        url.query_pairs_mut().append_pair("force", "true");
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.secret)
            .json(&ConfigReloadRequest { path })
            .send()
            .await
            .map_err(|_| ControllerError::Request)?;
        if response.status().is_success() || response.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(ControllerError::Http(response.status()))
        }
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, ControllerError> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.path_segments_mut()
            .map_err(|()| ControllerError::InvalidAddress)?
            .clear()
            .extend(segments.iter().copied());
        Ok(url)
    }
}

fn selector_snapshot(
    selector: &str,
    response: &ProxiesResponse,
) -> Result<SelectorNodeSnapshot, ControllerError> {
    let group = response
        .proxies
        .get(selector)
        .ok_or(ControllerError::Response)?;
    let current_node = if group.now.is_empty() {
        None
    } else {
        Some(group.now.clone())
    };
    let nodes = group
        .all
        .iter()
        .map(|name| {
            let detail = response.proxies.get(name);
            let proxy_type = detail
                .map(|proxy| proxy.proxy_type.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or("Unknown")
                .to_owned();
            let latency_ms = detail.and_then(|proxy| {
                proxy
                    .history
                    .iter()
                    .rev()
                    .find_map(|entry| (entry.delay > 0).then_some(entry.delay))
            });
            SubscriptionNode {
                name: name.clone(),
                proxy_type,
                alive: detail.and_then(|proxy| proxy.alive),
                latency_ms,
            }
        })
        .collect();
    Ok(SelectorNodeSnapshot {
        current_node,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2_048];
        loop {
            let read = stream.read(&mut buffer).expect("Controller request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .or_else(|| line.strip_prefix("Content-Length: "))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or_default();
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8(request).expect("UTF-8 HTTP request")
    }

    fn write_json_response(stream: &mut std::net::TcpStream, body: &serde_json::Value) {
        let body = serde_json::to_vec(body).expect("Controller response");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("response headers");
        stream.write_all(&body).expect("response body");
    }

    #[test]
    fn rejects_remote_controller() {
        assert!(matches!(
            ControllerClient::new("http://192.0.2.1:9090", "secret".into(), 100),
            Err(ControllerError::InvalidAddress)
        ));
    }

    #[test]
    fn parses_only_safe_selector_node_fields_in_selector_order() {
        let response = serde_json::from_value::<ProxiesResponse>(serde_json::json!({
            "proxies": {
                "vpn-hub-outlet-demo": {
                    "type": "Selector",
                    "now": "Synthetic Beta",
                    "all": ["Synthetic Alpha", "Synthetic Beta"]
                },
                "Synthetic Alpha": {
                    "type": "Vless",
                    "alive": true,
                    "history": [{"time": "2026-07-21T00:00:00Z", "delay": 0}, {"delay": 48}],
                    "server": "must-not-be-deserialized.invalid",
                    "port": 443
                },
                "Synthetic Beta": {
                    "type": "Trojan",
                    "alive": false,
                    "history": [{"delay": 95}],
                    "password": "must-not-be-deserialized"
                }
            }
        }))
        .expect("synthetic Controller response");

        let snapshot = selector_snapshot("vpn-hub-outlet-demo", &response).expect("selector");
        assert_eq!(snapshot.current_node.as_deref(), Some("Synthetic Beta"));
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["Synthetic Alpha", "Synthetic Beta"]
        );
        assert_eq!(snapshot.nodes[0].proxy_type, "Vless");
        assert_eq!(snapshot.nodes[0].alive, Some(true));
        assert_eq!(snapshot.nodes[0].latency_ms, Some(48));
        assert_eq!(snapshot.nodes[1].alive, Some(false));
    }

    #[test]
    fn tolerates_missing_optional_node_health_fields() {
        let response = serde_json::from_value::<ProxiesResponse>(serde_json::json!({
            "proxies": {
                "vpn-hub-outlet-demo": {
                    "now": "Synthetic Unknown",
                    "all": ["Synthetic Unknown"]
                }
            }
        }))
        .expect("minimal Controller response");

        let snapshot = selector_snapshot("vpn-hub-outlet-demo", &response).expect("selector");
        assert_eq!(snapshot.nodes[0].proxy_type, "Unknown");
        assert_eq!(snapshot.nodes[0].alive, None);
        assert_eq!(snapshot.nodes[0].latency_ms, None);
    }

    #[tokio::test]
    async fn reads_multiple_selector_snapshots_with_one_controller_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback Controller");
        let address = listener.local_addr().expect("Controller address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("Controller connection");
            let request = read_request(&mut stream);
            assert!(request.starts_with("GET /proxies "));
            assert!(request.contains("authorization: Bearer test-secret"));
            write_json_response(
                &mut stream,
                &serde_json::json!({
                    "proxies": {
                        "vpn-hub-outlet-a": {
                            "type": "URLTest",
                            "now": "Synthetic Alpha",
                            "all": ["Synthetic Alpha"]
                        },
                        "vpn-hub-outlet-b": {
                            "type": "URLTest",
                            "now": "Synthetic Beta",
                            "all": ["Synthetic Beta"]
                        },
                        "Synthetic Alpha": {"type": "Vless", "alive": true},
                        "Synthetic Beta": {"type": "Trojan", "alive": true}
                    }
                }),
            );
        });
        let client =
            ControllerClient::new(&format!("http://{address}"), "test-secret".into(), 2_000)
                .expect("Controller client");

        let snapshots = client
            .selector_nodes_for(&[
                "vpn-hub-outlet-a".into(),
                "vpn-hub-outlet-b".into(),
                "vpn-hub-outlet-missing".into(),
            ])
            .await
            .expect("selector catalog");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots["vpn-hub-outlet-a"].current_node.as_deref(),
            Some("Synthetic Alpha")
        );
        assert!(!snapshots.contains_key("vpn-hub-outlet-missing"));
        server.join().expect("Controller server");
    }

    #[tokio::test]
    async fn validates_candidate_selects_and_reads_authoritative_node_back() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback Controller");
        let address = listener.local_addr().expect("Controller address");
        let server = thread::spawn(move || {
            let mut current = "Synthetic Alpha";
            for step in 0..3 {
                let (mut stream, _) = listener.accept().expect("Controller connection");
                let request = read_request(&mut stream);
                assert!(request.contains("authorization: Bearer test-secret"));
                if step == 1 {
                    assert!(request.starts_with("PUT /proxies/vpn-hub-outlet-demo "));
                    assert!(request.contains(r#"{"name":"Synthetic Beta"}"#));
                    current = "Synthetic Beta";
                    stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .expect("selection response");
                    continue;
                }
                assert!(request.starts_with("GET /proxies "));
                write_json_response(
                    &mut stream,
                    &serde_json::json!({
                        "proxies": {
                            "vpn-hub-outlet-demo": {
                                "type": "Selector",
                                "now": current,
                                "all": ["Synthetic Alpha", "Synthetic Beta"]
                            },
                            "Synthetic Alpha": {"type": "Vless", "alive": true},
                            "Synthetic Beta": {"type": "Trojan", "alive": true}
                        }
                    }),
                );
            }
        });
        let client =
            ControllerClient::new(&format!("http://{address}"), "test-secret".into(), 2_000)
                .expect("Controller client");

        let snapshot = client
            .select_selector_node("vpn-hub-outlet-demo", "Synthetic Beta")
            .await
            .expect("confirmed selection");
        assert_eq!(snapshot.current_node.as_deref(), Some("Synthetic Beta"));
        server.join().expect("Controller server");
    }

    #[tokio::test]
    async fn reports_unconfirmed_when_selection_readback_disagrees() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback Controller");
        let address = listener.local_addr().expect("Controller address");
        let server = thread::spawn(move || {
            for step in 0..3 {
                let (mut stream, _) = listener.accept().expect("Controller connection");
                let request = read_request(&mut stream);
                if step == 1 {
                    assert!(request.starts_with("PUT /proxies/vpn-hub-outlet-demo "));
                    stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .expect("selection response");
                    continue;
                }
                assert!(request.starts_with("GET /proxies "));
                write_json_response(
                    &mut stream,
                    &serde_json::json!({
                        "proxies": {
                            "vpn-hub-outlet-demo": {
                                "type": "URLTest",
                                "now": "Synthetic Alpha",
                                "all": ["Synthetic Alpha", "Synthetic Beta"]
                            },
                            "Synthetic Alpha": {"type": "Vless", "alive": true},
                            "Synthetic Beta": {"type": "Trojan", "alive": true}
                        }
                    }),
                );
            }
        });
        let client =
            ControllerClient::new(&format!("http://{address}"), "test-secret".into(), 2_000)
                .expect("Controller client");

        let error = client
            .select_selector_node("vpn-hub-outlet-demo", "Synthetic Beta")
            .await
            .expect_err("mismatched readback must not report success");
        assert!(matches!(error, ControllerError::SelectionUnconfirmed));
        server.join().expect("Controller server");
    }
}
