#[cfg(target_os = "windows")]
mod windows {
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use rand::{Rng, distr::Alphanumeric};
    use serde::Serialize;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{ClientOptions, ServerOptions},
        time::timeout,
    };

    use crate::{
        AuthenticatedRequest, Command, PROTOCOL_VERSION, ProtocolKey, ReplayCache, SignedRequest,
        UnsignedRequest, authenticate_challenged_frame, pipe_name,
    };

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_FRAME_BYTES: usize = 64 * 1024;

    #[derive(Debug, thiserror::Error)]
    pub enum TransportError {
        #[error("named pipe server unavailable")]
        Fatal,
        #[error("named pipe connection rejected")]
        Connection,
    }

    #[derive(Serialize)]
    struct WireError {
        ok: bool,
        error: &'static str,
    }

    pub async fn serve_one_named_pipe_request<F>(
        install_id: &str,
        interactive_user_sid: &str,
        key: Arc<ProtocolKey>,
        replay: Arc<tokio::sync::Mutex<ReplayCache>>,
        handler: F,
    ) -> Result<(), TransportError>
    where
        F: FnOnce(AuthenticatedRequest) -> Vec<u8>,
    {
        let name = pipe_name(install_id).map_err(|_| TransportError::Fatal)?;
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .in_buffer_size(u32::try_from(MAX_FRAME_BYTES).map_err(|_| TransportError::Fatal)?)
            .out_buffer_size(u32::try_from(MAX_FRAME_BYTES).map_err(|_| TransportError::Fatal)?);
        let mut server = vpn_hub_windows_security::create_restricted_named_pipe(
            &options,
            &name,
            interactive_user_sid,
        )
        .map_err(|_| TransportError::Fatal)?;
        timeout(IO_TIMEOUT, server.connect())
            .await
            .map_err(|_| TransportError::Connection)?
            .map_err(|_| TransportError::Connection)?;
        let challenge = random_token(32);
        if write_frame(&mut server, challenge.as_bytes())
            .await
            .is_err()
        {
            replay.lock().await.record_transport_rejection(unix_ms());
            return Err(TransportError::Connection);
        }
        let Ok(frame) = read_frame(&mut server).await else {
            replay.lock().await.record_transport_rejection(unix_ms());
            return Err(TransportError::Connection);
        };
        let mut replay = replay.lock().await;
        let response = match authenticate_challenged_frame(
            &frame,
            &key,
            install_id,
            &challenge,
            unix_ms(),
            &mut replay,
        ) {
            Ok(request) => handler(request),
            Err(_) => serde_json::to_vec(&WireError {
                ok: false,
                error: "request rejected",
            })
            .map_err(|_| TransportError::Fatal)?,
        };
        write_frame(&mut server, &response)
            .await
            .map_err(|_| TransportError::Connection)
    }

    pub struct NamedPipeClient {
        install_id: String,
        key: Arc<ProtocolKey>,
    }

    impl NamedPipeClient {
        #[must_use]
        pub fn new(install_id: String, key: Arc<ProtocolKey>) -> Self {
            Self { install_id, key }
        }

        pub async fn send(&self, command: Command) -> Result<Vec<u8>, String> {
            let name = pipe_name(&self.install_id).map_err(|error| error.to_string())?;
            let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
            let mut client = loop {
                match ClientOptions::new().open(&name) {
                    Ok(client) => break client,
                    Err(error)
                        if matches!(error.raw_os_error(), Some(2 | 231))
                            && tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => {
                        return Err(format!("named pipe open failed: {error}"));
                    }
                }
            };
            let challenge = String::from_utf8(read_frame(&mut client).await?)
                .map_err(|_| "invalid challenge".to_owned())?;
            let now = unix_ms();
            let signed = SignedRequest::new(
                UnsignedRequest {
                    version: PROTOCOL_VERSION,
                    request_id: random_token(24),
                    install_id: self.install_id.clone(),
                    issued_at_unix_ms: now,
                    expires_at_unix_ms: now.saturating_add(10_000),
                    nonce: random_token(32),
                    challenge,
                    command,
                },
                &self.key,
            );
            let frame = serde_json::to_vec(&signed).map_err(|error| error.to_string())?;
            write_frame(&mut client, &frame).await?;
            read_frame(&mut client).await
        }
    }

    async fn read_frame<T>(io: &mut T) -> Result<Vec<u8>, String>
    where
        T: AsyncReadExt + Unpin,
    {
        let length = timeout(IO_TIMEOUT, io.read_u32_le())
            .await
            .map_err(|_| "named pipe read timeout".to_owned())?
            .map_err(|error| format!("named pipe read failed: {error}"))?
            as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err("named pipe frame rejected".into());
        }
        let mut frame = vec![0_u8; length];
        timeout(IO_TIMEOUT, io.read_exact(&mut frame))
            .await
            .map_err(|_| "named pipe read timeout".to_owned())?
            .map_err(|error| format!("named pipe read failed: {error}"))?;
        Ok(frame)
    }

    async fn write_frame<T>(io: &mut T, frame: &[u8]) -> Result<(), String>
    where
        T: AsyncWriteExt + Unpin,
    {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err("named pipe frame rejected".into());
        }
        timeout(IO_TIMEOUT, async {
            io.write_u32_le(u32::try_from(frame.len()).map_err(std::io::Error::other)?)
                .await?;
            io.write_all(frame).await?;
            io.flush().await
        })
        .await
        .map_err(|_| "named pipe write timeout".to_owned())?
        .map_err(|error| format!("named pipe write failed: {error}"))
    }

    fn random_token(length: usize) -> String {
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    fn unix_ms() -> i64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        i64::try_from(millis).unwrap_or(i64::MAX)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        async fn open_test_client(name: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
            let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
            loop {
                match ClientOptions::new().open(name) {
                    Ok(client) => return client,
                    Err(error)
                        if matches!(error.raw_os_error(), Some(2 | 231))
                            && tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("test pipe open failed: {error}"),
                }
            }
        }

        #[tokio::test]
        async fn actual_local_pipe_round_trip_is_authenticated() {
            let install_id = format!("test-{}", random_token(16));
            let key = Arc::new(ProtocolKey::from_bytes([29; 32]));
            let server_key = Arc::clone(&key);
            let server_install_id = install_id.clone();
            let target_sid = vpn_hub_windows_security::lookup_local_account_sid(
                &std::env::var("USERNAME").unwrap(),
            )
            .unwrap();
            let server = tokio::spawn(async move {
                serve_one_named_pipe_request(
                    &server_install_id,
                    &target_sid,
                    server_key,
                    Arc::new(tokio::sync::Mutex::new(ReplayCache::default())),
                    |request| format!("accepted:{:?}", request.command).into_bytes(),
                )
                .await
            });
            tokio::task::yield_now().await;
            let client = NamedPipeClient::new(install_id, key);
            let response = client.send(Command::Status).await.unwrap();
            assert_eq!(response, b"accepted:Status");
            server.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn hostile_connections_are_discarded_and_next_valid_request_succeeds() {
            let install_id = format!("test-{}", random_token(16));
            let name = pipe_name(&install_id).unwrap();
            let key = Arc::new(ProtocolKey::from_bytes([41; 32]));
            let replay = Arc::new(tokio::sync::Mutex::new(ReplayCache::default()));
            let target_sid = vpn_hub_windows_security::lookup_local_account_sid(
                &std::env::var("USERNAME").unwrap(),
            )
            .unwrap();

            for attack in 0..3 {
                let server_install_id = install_id.clone();
                let server_key = Arc::clone(&key);
                let server_replay = Arc::clone(&replay);
                let server_sid = target_sid.clone();
                let server = tokio::spawn(async move {
                    serve_one_named_pipe_request(
                        &server_install_id,
                        &server_sid,
                        server_key,
                        server_replay,
                        |_| b"unexpected".to_vec(),
                    )
                    .await
                });
                let mut client = open_test_client(&name).await;
                if attack == 0 {
                    drop(client);
                } else {
                    let _challenge = read_frame(&mut client).await.unwrap();
                    if attack == 1 {
                        client
                            .write_u32_le(u32::try_from(MAX_FRAME_BYTES + 1).unwrap())
                            .await
                            .unwrap();
                    } else {
                        client.write_u32_le(12).await.unwrap();
                        client.write_all(b"cut").await.unwrap();
                    }
                    client.flush().await.unwrap();
                    drop(client);
                }
                assert!(matches!(
                    server.await.unwrap(),
                    Err(TransportError::Connection)
                ));
            }

            let server_install_id = install_id.clone();
            let server_key = Arc::clone(&key);
            let server = tokio::spawn(async move {
                serve_one_named_pipe_request(
                    &server_install_id,
                    &target_sid,
                    server_key,
                    replay,
                    |request| format!("accepted:{:?}", request.command).into_bytes(),
                )
                .await
            });
            let response = NamedPipeClient::new(install_id, key)
                .send(Command::Status)
                .await
                .unwrap();
            assert_eq!(response, b"accepted:Status");
            server.await.unwrap().unwrap();
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::{NamedPipeClient, TransportError, serve_one_named_pipe_request};
