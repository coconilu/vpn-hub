use std::time::Duration;

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
}

#[derive(Debug, Deserialize)]
struct DelayResponse {
    delay: u64,
}

#[derive(Debug, Deserialize)]
struct ProxyResponse {
    now: String,
}

#[derive(Debug, Serialize)]
struct SelectionRequest<'a> {
    name: &'a str,
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
            .json::<ProxyResponse>()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_controller() {
        assert!(matches!(
            ControllerClient::new("http://192.0.2.1:9090", "secret".into(), 100),
            Err(ControllerError::InvalidAddress)
        ));
    }
}
