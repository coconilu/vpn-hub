use std::collections::{HashMap, VecDeque};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::PROTOCOL_VERSION;

const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 12;
const MAX_FIELD_BYTES: usize = 128;
const MAX_TTL_MS: i64 = 30_000;
const CLOCK_SKEW_MS: i64 = 5_000;
const MAX_REQUESTS_PER_WINDOW: u32 = 120;
const RATE_WINDOW_MS: i64 = 60_000;
const MAX_REPLAY_ENTRIES: usize = 2_048;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Command {
    Status,
    Version,
    Start,
    Stop,
    StopIfOwned(ExpectedOwnership),
    Restart,
    Reload,
    Resume,
    NetworkChanged,
    ResetCircuit,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOwnership {
    pub pid: u32,
    pub creation_identity: u64,
    pub fencing_epoch: u64,
    pub generation: u64,
}

impl Command {
    fn canonical_value(self) -> String {
        match self {
            Self::Status => "status".into(),
            Self::Version => "version".into(),
            Self::Start => "start".into(),
            Self::Stop => "stop".into(),
            Self::StopIfOwned(expected) => format!(
                "stop-if-owned:{}:{}:{}:{}",
                expected.pid,
                expected.creation_identity,
                expected.fencing_epoch,
                expected.generation
            ),
            Self::Restart => "restart".into(),
            Self::Reload => "reload".into(),
            Self::Resume => "resume".into(),
            Self::NetworkChanged => "network-changed".into(),
            Self::ResetCircuit => "reset-circuit".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedRequest {
    pub version: u16,
    pub request_id: String,
    pub install_id: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub nonce: String,
    pub challenge: String,
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    #[serde(flatten)]
    pub request: UnsignedRequest,
    pub mac_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedRequest {
    pub request_id: String,
    pub install_id: String,
    pub nonce: String,
    pub challenge: String,
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedResponse {
    pub version: u16,
    pub request_id: String,
    pub install_id: String,
    pub nonce: String,
    pub challenge: String,
    pub command: Command,
    pub payload_sha256: String,
    pub payload_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedResponse {
    #[serde(flatten)]
    pub response: UnsignedResponse,
    pub mac_hex: String,
}

/// An in-memory protocol key. It is intentionally neither serializable nor
/// printable and is wiped when dropped.
pub struct ProtocolKey([u8; 32]);

impl ProtocolKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Decodes an exact 32-byte lower-case hex key from protected storage.
    ///
    /// # Errors
    /// Returns a sanitized authentication error for invalid key material.
    pub fn from_hex(value: &str) -> Result<Self, AuthError> {
        decode_hex_32(value)
            .map(Self)
            .ok_or(AuthError::AuthenticationFailed)
    }

    fn sign(&self, payload: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts 32-byte keys");
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts 32-byte keys");
        mac.update(payload);
        mac.verify_slice(signature).is_ok()
    }
}

impl Drop for ProtocolKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SignedRequest {
    /// Signs the fixed request schema. There is no generic argument or path
    /// field in this protocol by design.
    #[must_use]
    pub fn new(request: UnsignedRequest, key: &ProtocolKey) -> Self {
        let mac_hex = encode_hex(&key.sign(&canonical_bytes(&request)));
        Self { request, mac_hex }
    }
}

impl SignedResponse {
    #[must_use]
    pub fn new(request: &AuthenticatedRequest, payload: &[u8], key: &ProtocolKey) -> Self {
        let response = UnsignedResponse {
            version: PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            install_id: request.install_id.clone(),
            nonce: request.nonce.clone(),
            challenge: request.challenge.clone(),
            command: request.command,
            payload_sha256: encode_hex(&Sha256::digest(payload)),
            payload_hex: encode_hex(payload),
        };
        let mac_hex = encode_hex(&key.sign(&canonical_response_bytes(&response)));
        Self { response, mac_hex }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    #[error("request rejected: malformed frame")]
    Malformed,
    #[error("request rejected: unsupported protocol version")]
    UnsupportedVersion,
    #[error("request rejected: invalid authentication")]
    AuthenticationFailed,
    #[error("request rejected: expired or invalid timestamp")]
    TimestampRejected,
    #[error("request rejected: replay detected")]
    ReplayDetected,
    #[error("request rejected: rate limited")]
    RateLimited,
    #[error("request rejected: wrong installation")]
    WrongInstallation,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashMap<String, i64>,
    order: VecDeque<String>,
    rate_window_started_at: Option<i64>,
    requests_in_window: u32,
}

impl ReplayCache {
    fn check_rate(&mut self, now_ms: i64) -> Result<(), AuthError> {
        let reset = self
            .rate_window_started_at
            .is_none_or(|started| now_ms.saturating_sub(started) >= RATE_WINDOW_MS);
        if reset {
            self.rate_window_started_at = Some(now_ms);
            self.requests_in_window = 0;
        }
        if self.requests_in_window >= MAX_REQUESTS_PER_WINDOW {
            return Err(AuthError::RateLimited);
        }
        self.requests_in_window += 1;
        Ok(())
    }

    pub(crate) fn record_transport_rejection(&mut self, now_ms: i64) {
        let _ = self.check_rate(now_ms);
    }

    fn reject_or_insert(
        &mut self,
        nonce: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<(), AuthError> {
        while self.order.front().is_some_and(|candidate| {
            self.seen
                .get(candidate)
                .is_none_or(|expiry| *expiry < now_ms)
        }) {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
        if self.seen.contains_key(nonce) {
            return Err(AuthError::ReplayDetected);
        }
        while self.order.len() >= MAX_REPLAY_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(nonce.to_owned(), expires_at_ms);
        self.order.push_back(nonce.to_owned());
        Ok(())
    }
}

/// Validates framing, version, installation binding, freshness, rate, HMAC and
/// replay protection, in that order. Errors never echo attacker-controlled data.
pub fn authenticate_challenged_frame(
    frame: &[u8],
    key: &ProtocolKey,
    expected_install_id: &str,
    expected_challenge: &str,
    now_ms: i64,
    replay: &mut ReplayCache,
) -> Result<AuthenticatedRequest, AuthError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES || json_depth(frame) > MAX_JSON_DEPTH {
        return Err(AuthError::Malformed);
    }
    replay.check_rate(now_ms)?;
    let signed: SignedRequest = serde_json::from_slice(frame).map_err(|_| AuthError::Malformed)?;
    validate_field(&signed.request.request_id)?;
    validate_field(&signed.request.install_id)?;
    validate_field(&signed.request.nonce)?;
    validate_field(&signed.request.challenge)?;
    if signed.request.version != PROTOCOL_VERSION {
        return Err(AuthError::UnsupportedVersion);
    }
    if signed.request.install_id != expected_install_id {
        return Err(AuthError::WrongInstallation);
    }
    if signed.request.challenge != expected_challenge {
        return Err(AuthError::AuthenticationFailed);
    }
    validate_timestamp(&signed.request, now_ms)?;
    let signature = decode_hex_32(&signed.mac_hex).ok_or(AuthError::AuthenticationFailed)?;
    if !key.verify(&canonical_bytes(&signed.request), &signature) {
        return Err(AuthError::AuthenticationFailed);
    }
    replay.reject_or_insert(
        &signed.request.nonce,
        signed.request.expires_at_unix_ms,
        now_ms,
    )?;
    Ok(AuthenticatedRequest {
        request_id: signed.request.request_id,
        install_id: signed.request.install_id,
        nonce: signed.request.nonce,
        challenge: signed.request.challenge,
        command: signed.request.command,
    })
}

pub fn authenticate_response_frame(
    frame: &[u8],
    key: &ProtocolKey,
    expected_request: &AuthenticatedRequest,
) -> Result<Vec<u8>, AuthError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES || json_depth(frame) > MAX_JSON_DEPTH {
        return Err(AuthError::Malformed);
    }
    let signed: SignedResponse = serde_json::from_slice(frame).map_err(|_| AuthError::Malformed)?;
    let response = &signed.response;
    if response.version != PROTOCOL_VERSION {
        return Err(AuthError::UnsupportedVersion);
    }
    if response.install_id != expected_request.install_id {
        return Err(AuthError::WrongInstallation);
    }
    if response.request_id != expected_request.request_id
        || response.nonce != expected_request.nonce
        || response.challenge != expected_request.challenge
        || response.command != expected_request.command
    {
        return Err(AuthError::AuthenticationFailed);
    }
    for value in [
        &response.request_id,
        &response.install_id,
        &response.nonce,
        &response.challenge,
    ] {
        validate_field(value)?;
    }
    let signature = decode_hex_32(&signed.mac_hex).ok_or(AuthError::AuthenticationFailed)?;
    if !key.verify(&canonical_response_bytes(response), &signature) {
        return Err(AuthError::AuthenticationFailed);
    }
    let payload = decode_hex(&response.payload_hex).ok_or(AuthError::Malformed)?;
    let digest = decode_hex_32(&response.payload_sha256).ok_or(AuthError::Malformed)?;
    if Sha256::digest(&payload).as_slice() != digest {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(payload)
}

/// Headless verification helper. Production transports must use
/// [`authenticate_challenged_frame`] with the challenge they generated before
/// reading the request.
#[cfg(test)]
fn authenticate_frame(
    frame: &[u8],
    key: &ProtocolKey,
    expected_install_id: &str,
    now_ms: i64,
    replay: &mut ReplayCache,
) -> Result<AuthenticatedRequest, AuthError> {
    let signed: SignedRequest = serde_json::from_slice(frame).map_err(|_| AuthError::Malformed)?;
    authenticate_challenged_frame(
        frame,
        key,
        expected_install_id,
        &signed.request.challenge,
        now_ms,
        replay,
    )
}

fn validate_timestamp(request: &UnsignedRequest, now_ms: i64) -> Result<(), AuthError> {
    let ttl = request
        .expires_at_unix_ms
        .checked_sub(request.issued_at_unix_ms)
        .ok_or(AuthError::TimestampRejected)?;
    if !(1..=MAX_TTL_MS).contains(&ttl)
        || request.issued_at_unix_ms > now_ms.saturating_add(CLOCK_SKEW_MS)
        || request.expires_at_unix_ms < now_ms
    {
        return Err(AuthError::TimestampRejected);
    }
    Ok(())
}

fn validate_field(value: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AuthError::Malformed);
    }
    Ok(())
}

fn canonical_bytes(request: &UnsignedRequest) -> Vec<u8> {
    format!(
        "vpn-hub-helper\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        request.version,
        request.request_id,
        request.install_id,
        request.issued_at_unix_ms,
        request.expires_at_unix_ms,
        request.nonce,
        request.challenge,
        request.command.canonical_value()
    )
    .into_bytes()
}

fn canonical_response_bytes(response: &UnsignedResponse) -> Vec<u8> {
    format!(
        "vpn-hub-helper-response\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        response.version,
        response.request_id,
        response.install_id,
        response.nonce,
        response.challenge,
        response.command.canonical_value(),
        response.payload_sha256,
    )
    .into_bytes()
}

fn json_depth(frame: &[u8]) -> usize {
    let mut depth = 0_usize;
    let mut max_depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in frame {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                max_depth = max_depth.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max_depth
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(output)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > MAX_FRAME_BYTES {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedPipeContract {
    pub name: String,
    pub allowed_principals: [&'static str; 3],
    pub remote_clients_rejected: bool,
    pub max_frame_bytes: usize,
    pub request_timeout_ms: u64,
}

impl NamedPipeContract {
    pub fn for_install(install_id: &str) -> Result<Self, AuthError> {
        validate_field(install_id)?;
        Ok(Self {
            name: pipe_name(install_id)?,
            allowed_principals: [
                "interactive-user-sid",
                "NT AUTHORITY\\LOCAL SERVICE",
                "SYSTEM",
            ],
            remote_clients_rejected: true,
            max_frame_bytes: MAX_FRAME_BYTES,
            request_timeout_ms: 5_000,
        })
    }
}

pub fn pipe_name(install_id: &str) -> Result<String, AuthError> {
    validate_field(install_id)?;
    Ok(format!(r"\\.\pipe\vpn-hub-{install_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: Command) -> UnsignedRequest {
        UnsignedRequest {
            version: PROTOCOL_VERSION,
            request_id: "request-1".into(),
            install_id: "install-a".into(),
            issued_at_unix_ms: 10_000,
            expires_at_unix_ms: 20_000,
            nonce: "0123456789abcdef".into(),
            challenge: "server-challenge".into(),
            command,
        }
    }

    fn frame(request: UnsignedRequest, key: &ProtocolKey) -> Vec<u8> {
        serde_json::to_vec(&SignedRequest::new(request, key)).unwrap()
    }

    #[test]
    fn signed_request_authenticates_and_is_bound_to_command() {
        let key = ProtocolKey::from_bytes([7; 32]);
        let mut replay = ReplayCache::default();
        let frame = frame(request(Command::Restart), &key);
        let authenticated =
            authenticate_frame(&frame, &key, "install-a", 15_000, &mut replay).unwrap();
        assert_eq!(authenticated.command, Command::Restart);

        let mut tampered: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        tampered["command"] = "stop".into();
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert_eq!(
            authenticate_frame(
                &tampered,
                &key,
                "install-a",
                15_000,
                &mut ReplayCache::default()
            ),
            Err(AuthError::AuthenticationFailed)
        );
    }

    #[test]
    fn stop_if_owned_authentication_binds_every_identity_field() {
        let key = ProtocolKey::from_bytes([9; 32]);
        let expected = ExpectedOwnership {
            pid: 40_001,
            creation_identity: 91,
            fencing_epoch: 7,
            generation: 3,
        };
        let frame = frame(request(Command::StopIfOwned(expected)), &key);
        let authenticated = authenticate_frame(
            &frame,
            &key,
            "install-a",
            15_000,
            &mut ReplayCache::default(),
        )
        .unwrap();
        assert_eq!(authenticated.command, Command::StopIfOwned(expected));

        for field in ["pid", "creation_identity", "fencing_epoch", "generation"] {
            let mut tampered: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            tampered["command"]["stop-if-owned"][field] = 1.into();
            assert_eq!(
                authenticate_frame(
                    &serde_json::to_vec(&tampered).unwrap(),
                    &key,
                    "install-a",
                    15_000,
                    &mut ReplayCache::default(),
                ),
                Err(AuthError::AuthenticationFailed),
                "{field} must be HMAC-bound"
            );
        }
    }

    #[test]
    fn signed_response_is_bound_to_request_and_payload() {
        let key = ProtocolKey::from_bytes([13; 32]);
        let request = AuthenticatedRequest {
            request_id: "request-1".into(),
            install_id: "install-a".into(),
            nonce: "nonce-1".into(),
            challenge: "challenge-1".into(),
            command: Command::Status,
        };
        let signed = SignedResponse::new(&request, b"payload", &key);
        let frame = serde_json::to_vec(&signed).unwrap();
        assert_eq!(
            authenticate_response_frame(&frame, &key, &request).unwrap(),
            b"payload"
        );
        let mut wrong_request = request.clone();
        wrong_request.request_id = "request-2".into();
        assert_eq!(
            authenticate_response_frame(&frame, &key, &wrong_request),
            Err(AuthError::AuthenticationFailed)
        );
        let mut tampered: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        tampered["payload_hex"] = "00".into();
        assert_eq!(
            authenticate_response_frame(&serde_json::to_vec(&tampered).unwrap(), &key, &request),
            Err(AuthError::AuthenticationFailed)
        );
    }

    #[test]
    fn missing_auth_old_version_replay_and_timestamp_are_rejected() {
        let key = ProtocolKey::from_bytes([11; 32]);
        let unsigned = serde_json::to_vec(&request(Command::Status)).unwrap();
        assert_eq!(
            authenticate_frame(
                &unsigned,
                &key,
                "install-a",
                15_000,
                &mut ReplayCache::default()
            ),
            Err(AuthError::Malformed)
        );

        let mut old = request(Command::Status);
        old.version = 0;
        assert_eq!(
            authenticate_frame(
                &frame(old, &key),
                &key,
                "install-a",
                15_000,
                &mut ReplayCache::default()
            ),
            Err(AuthError::UnsupportedVersion)
        );

        let signed = frame(request(Command::Status), &key);
        let mut replay = ReplayCache::default();
        authenticate_frame(&signed, &key, "install-a", 15_000, &mut replay).unwrap();
        assert_eq!(
            authenticate_frame(&signed, &key, "install-a", 15_000, &mut replay),
            Err(AuthError::ReplayDetected)
        );

        assert_eq!(
            authenticate_frame(
                &signed,
                &key,
                "install-a",
                20_001,
                &mut ReplayCache::default()
            ),
            Err(AuthError::TimestampRejected)
        );
    }

    #[test]
    fn bounded_frame_depth_and_rate_are_enforced() {
        let key = ProtocolKey::from_bytes([13; 32]);
        let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert_eq!(
            authenticate_frame(
                &oversized,
                &key,
                "install-a",
                15_000,
                &mut ReplayCache::default()
            ),
            Err(AuthError::Malformed)
        );

        let deep = format!("{}0{}", "[".repeat(13), "]".repeat(13));
        assert_eq!(
            authenticate_frame(
                deep.as_bytes(),
                &key,
                "install-a",
                15_000,
                &mut ReplayCache::default()
            ),
            Err(AuthError::Malformed)
        );

        let mut replay = ReplayCache::default();
        for index in 0..MAX_REQUESTS_PER_WINDOW {
            let mut next = request(Command::Version);
            next.request_id = format!("request-{index}");
            next.nonce = format!("nonce-{index}");
            authenticate_frame(&frame(next, &key), &key, "install-a", 15_000, &mut replay).unwrap();
        }
        let mut limited = request(Command::Version);
        limited.nonce = "rate-limit".into();
        assert_eq!(
            authenticate_frame(
                &frame(limited, &key),
                &key,
                "install-a",
                15_000,
                &mut replay
            ),
            Err(AuthError::RateLimited)
        );
    }

    #[test]
    fn named_pipe_is_install_bound_and_never_tcp() {
        let contract = NamedPipeContract::for_install("install-a").unwrap();
        assert_eq!(contract.name, r"\\.\pipe\vpn-hub-install-a");
        assert!(contract.remote_clients_rejected);
        assert!(!contract.name.contains("tcp"));
        assert!(pipe_name("../escape").is_err());
    }
}
