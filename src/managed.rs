//! Optional parent-owned lifecycle, separate from the public HTTP router.
//!
//! The parent supplies a fresh launch ID and installation secret through stdin.
//! A bounded loopback control socket uses challenge-bound HMAC messages: an
//! unrelated process that reuses its port never receives the secret. EOF on the
//! private parent pipe shuts down a managed child after a parent crash.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};

pub const PROTOCOL: u32 = 1;
pub const READY_PREFIX: &str = "RAGNAROK_ASSET_READY ";
const MAX_MESSAGE: usize = 16384;
type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap {
    pub secret: String,
    pub launch_id: String,
    pub state_root: String,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub protocol: u32,
    pub service: String,
    pub version: String,
    pub pid: u32,
    pub launch_id: String,
    pub state_root: String,
    pub executable: String,
    pub executable_digest: String,
    pub config_fingerprint: String,
    pub control_port: u16,
    pub http_port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub launch_id: String,
    pub challenge: String,
    pub action: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn sign(secret: &[u8], payload: String) -> Envelope {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    Envelope {
        payload,
        mac: hex(&mac.finalize().into_bytes()),
    }
}

pub fn verify(secret: &[u8], envelope: &Envelope) -> bool {
    let Some(signature) = unhex(&envelope.mac) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(envelope.payload.as_bytes());
    mac.verify_slice(&signature).is_ok()
}

pub struct Managed {
    pub identity: Identity,
    shutdown: watch::Receiver<bool>,
}

impl Managed {
    /// The initial message is read before starting the server. stdin is a pipe
    /// only when the caller explicitly opts into --managed.
    pub fn bootstrap() -> Result<Bootstrap, String> {
        let input = std::io::stdin();
        let mut reader = input.lock();
        let mut line = Vec::new();
        std::io::Read::by_ref(&mut reader)
            .take(MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if line.len() > MAX_MESSAGE || !line.ends_with(b"\n") {
            return Err("invalid managed bootstrap message".into());
        }
        let bootstrap: Bootstrap =
            serde_json::from_slice(&line).map_err(|_| "invalid managed bootstrap JSON")?;
        if !valid_nonce(&bootstrap.secret) || !valid_nonce(&bootstrap.launch_id) {
            return Err("managed secret and launch ID must be 32-byte hex values".into());
        }
        if !std::path::Path::new(&bootstrap.state_root).is_absolute() {
            return Err("managed state root must be absolute".into());
        }
        for (key, value) in &bootstrap.environment {
            if std::env::var(key).ok().as_ref() != Some(value) {
                return Err(format!("managed configuration mismatch: {key}"));
            }
        }
        Ok(bootstrap)
    }

    pub async fn start(
        bootstrap: Bootstrap,
        http_port: u16,
    ) -> Result<(Self, watch::Sender<bool>), String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let bytes = std::fs::read(&exe).map_err(|e| e.to_string())?;
        let identity = Identity {
            protocol: PROTOCOL,
            service: "robrowser-remoteclient".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            pid: std::process::id(),
            launch_id: bootstrap.launch_id,
            state_root: bootstrap.state_root,
            executable: exe.to_string_lossy().into_owned(),
            executable_digest: hex(&Sha256::digest(bytes)),
            config_fingerprint: hex(&Sha256::digest(
                serde_json::to_vec(&bootstrap.environment).unwrap(),
            )),
            control_port: listener.local_addr().map_err(|e| e.to_string())?.port(),
            http_port,
        };
        let secret = Arc::new(unhex(&bootstrap.secret).unwrap());
        let (shutdown_tx, shutdown) = watch::channel(false);
        let id = identity.clone();
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(8));
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let (secret, identity, tx) = (secret.clone(), id.clone(), tx.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        control(stream, &secret, &identity, tx),
                    )
                    .await;
                });
            }
        });
        Ok((Self { identity, shutdown }, shutdown_tx))
    }

    pub fn announce(&self) -> Result<(), String> {
        // No secret is ever printed. stdout is the parent's private pipe.
        println!(
            "{READY_PREFIX}{}",
            serde_json::to_string(&self.identity).unwrap()
        );
        std::io::stdout().flush().map_err(|e| e.to_string())
    }

    pub async fn stopped(&mut self) {
        if !*self.shutdown.borrow() {
            let _ = self.shutdown.changed().await;
        }
    }
}

async fn control(
    stream: TcpStream,
    secret: &[u8],
    identity: &Identity,
    shutdown: watch::Sender<bool>,
) -> Result<(), std::io::Error> {
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    // fill_buf/consume bounds allocation even when the peer never sends a newline.
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(());
        }
        let end = chunk.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let n = end.unwrap_or(chunk.len());
        if bytes.len() + n > MAX_MESSAGE {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        reader.consume(n);
        if end.is_some() {
            break;
        }
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(&bytes) else {
        return Ok(());
    };
    if !verify(secret, &envelope) {
        return Ok(());
    }
    let Ok(request) = serde_json::from_str::<Request>(&envelope.payload) else {
        return Ok(());
    };
    if request.launch_id != identity.launch_id
        || !valid_nonce(&request.challenge)
        || !matches!(request.action.as_str(), "status" | "shutdown")
    {
        return Ok(());
    }
    let payload = serde_json::json!({
        "identity": identity, "challenge": request.challenge, "action": request.action,
    })
    .to_string();
    let mut reply = serde_json::to_vec(&sign(secret, payload)).unwrap();
    reply.push(b'\n');
    reader.get_mut().write_all(&reply).await?;
    reader.get_mut().shutdown().await?;
    if request.action == "shutdown" {
        let _ = shutdown.send(true);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rejects_tampering_and_wrong_keys() {
        let secret = [42u8; 32];
        let mut msg = sign(&secret, "request".into());
        assert!(verify(&secret, &msg));
        assert!(!verify(&[43u8; 32], &msg));
        msg.payload.push('!');
        assert!(!verify(&secret, &msg));
        msg.mac = "not hex".into();
        assert!(!verify(&secret, &msg));
    }

    #[test]
    fn standard_hmac_sha256_vector() {
        let signed = sign(&[0x0b; 20], "Hi There".into());
        assert_eq!(
            signed.mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
