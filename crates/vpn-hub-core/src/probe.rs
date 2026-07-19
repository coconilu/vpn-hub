use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use tokio::{net::TcpStream, time::timeout};

use crate::{HealthStatus, MonitorConfig, ProbeOutletConfig, ProbeResult};

pub async fn probe_outlet(outlet: &ProbeOutletConfig, monitor: &MonitorConfig) -> ProbeResult {
    let observed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut base = ProbeResult {
        outlet_id: outlet.id.clone(),
        label: outlet.label.clone(),
        observed_at,
        port_reachable: false,
        status: HealthStatus::Down,
        http_status: None,
        latency_ms: None,
        error_code: None,
        successful_targets: 0,
        total_targets: 1,
    };

    let Ok(socket_addr) = outlet.socket_addr() else {
        return failed(base, "invalid_proxy_config");
    };
    let connect_timeout = Duration::from_millis(monitor.connect_timeout_ms);
    match timeout(connect_timeout, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => drop(stream),
        Ok(Err(_)) => return failed(base, "port_unreachable"),
        Err(_) => return failed(base, "port_timeout"),
    }
    base.port_reachable = true;

    let Ok(proxy) = reqwest::Proxy::all(&outlet.proxy_url) else {
        return failed(base, "invalid_proxy_config");
    };
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .connect_timeout(connect_timeout)
        .timeout(Duration::from_millis(monitor.request_timeout_ms))
        .build()
    else {
        return failed(base, "client_build_failed");
    };

    let started = Instant::now();
    let response = client.get(&outlet.probe_url).send().await;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match response {
        Ok(response) if response.status().is_success() || response.status().is_redirection() => {
            let status_code = response.status().as_u16();
            ProbeResult {
                status: if elapsed_ms > outlet.degraded_latency_ms {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Healthy
                },
                http_status: Some(status_code),
                latency_ms: Some(elapsed_ms),
                successful_targets: 1,
                ..base
            }
        }
        Ok(response) => {
            base.http_status = Some(response.status().as_u16());
            failed(base, "unexpected_http_status")
        }
        Err(error) if error.is_timeout() => failed(base, "request_timeout"),
        Err(error) if error.is_connect() => failed(base, "proxy_connect_failed"),
        Err(_) => failed(base, "request_failed"),
    }
}

fn failed(mut result: ProbeResult, code: &str) -> ProbeResult {
    result.status = HealthStatus::Down;
    result.error_code = Some(code.to_owned());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_local_port_is_down() {
        let outlet = ProbeOutletConfig {
            id: "closed".into(),
            label: "Closed".into(),
            proxy_url: "socks5h://127.0.0.1:9".into(),
            probe_url: "https://example.com".into(),
            degraded_latency_ms: 2_500,
            enabled: true,
        };
        let monitor = MonitorConfig {
            interval_seconds: 15,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            failure_threshold: 2,
            recovery_threshold: 3,
        };

        let result = probe_outlet(&outlet, &monitor).await;
        assert_eq!(result.status, HealthStatus::Down);
        assert!(result.error_code.is_some());
    }
}
