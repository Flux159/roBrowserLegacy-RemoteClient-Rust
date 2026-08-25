//! WebSocket-to-TCP proxy.
//!
//! Browsers cannot open TCP sockets and rAthena speaks nothing else, so every
//! packet of the login, char and map sessions passes through here.  The rules
//! that matter: forward bytes untouched, disable Nagle, buffer whatever the
//! client sends before the TCP connection finishes opening, and tear both sides
//! down exactly once.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::parse_target;
use crate::{info, warn};

/// roBrowser sends its first game packet synchronously from `onopen`, which
/// races the TCP connect.  Without this buffer those packets are dropped and
/// the login screen simply hangs.
const MAX_PENDING: usize = 64;
const TCP_READ_BUFFER: usize = 16 * 1024;

pub async fn proxy(mut socket: WebSocket, target: String, allowed: Arc<Vec<String>>) {
    let Some((host, port)) = parse_target(&target) else {
        warn!("WS proxy rejected malformed target: \"{target}\"");
        let _ = socket.close().await;
        return;
    };

    info!("WS attempt: {target}");

    // The allowlist is the security boundary.  Without it this process is an
    // open TCP relay to anything it can route to.
    if !allowed.iter().any(|a| a == &target) {
        warn!(
            "WS proxy blocked: {target} (allowed: {})",
            allowed.join(", ")
        );
        let _ = socket.close().await;
        return;
    }

    info!("WS proxy: connecting to {target}");

    // A bracketed IPv6 literal has to lose its brackets before it can be
    // resolved, but the allowlist entry keeps them.
    let dial_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();

    let (mut ws_tx, mut ws_rx) = socket.split();

    let connect = TcpStream::connect((dial_host.as_str(), port));
    tokio::pin!(connect);

    let mut pending: Vec<Vec<u8>> = Vec::new();
    let stream = loop {
        tokio::select! {
            result = &mut connect => match result {
                Ok(stream) => break stream,
                Err(e) => {
                    warn!("WS proxy: closed {target} (server error: {e})");
                    let _ = ws_tx.close().await;
                    return;
                }
            },
            message = ws_rx.next() => match message {
                Some(Ok(Message::Binary(data))) => push_pending(&mut pending, data.to_vec(), &target),
                Some(Ok(Message::Text(text))) => {
                    push_pending(&mut pending, text.as_bytes().to_vec(), &target)
                }
                Some(Ok(Message::Close(_))) | None => {
                    info!("WS proxy: closed {target} (client closed)");
                    return;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    info!("WS proxy: closed {target} (client error: {e})");
                    return;
                }
            },
        }
    };

    // RO is a stream of small, latency-sensitive packets.  Nagle makes it feel
    // broken in a way that reads as lag rather than as a bug here.
    if let Err(e) = stream.set_nodelay(true) {
        warn!("WS proxy: could not set TCP_NODELAY on {target}: {e}");
    }

    info!("WS proxy: connected  to {target}");

    let (mut tcp_rx, mut tcp_tx) = stream.into_split();

    for buffered in pending.drain(..) {
        if tcp_tx.write_all(&buffered).await.is_err() {
            info!("WS proxy: closed {target} (server closed)");
            let _ = ws_tx.close().await;
            return;
        }
    }

    let client_to_server = async {
        while let Some(message) = ws_rx.next().await {
            let payload = match message {
                Ok(Message::Binary(data)) => data.to_vec(),
                Ok(Message::Text(text)) => text.as_bytes().to_vec(),
                Ok(Message::Close(_)) => return "client closed",
                Ok(_) => continue,
                Err(_) => return "client error",
            };
            if tcp_tx.write_all(&payload).await.is_err() {
                return "server closed";
            }
        }
        "client closed"
    };

    let server_to_client = async {
        let mut buffer = vec![0u8; TCP_READ_BUFFER];
        loop {
            match tcp_rx.read(&mut buffer).await {
                Ok(0) => return "server closed",
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buffer[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        return "client closed";
                    }
                }
                Err(_) => return "server error",
            }
        }
    };

    // Whichever direction ends first takes the other with it; dropping the
    // halves closes both sockets, and it happens exactly once.
    let reason = tokio::select! {
        reason = client_to_server => reason,
        reason = server_to_client => reason,
    };

    info!("WS proxy: closed {target} ({reason})");
}

fn push_pending(pending: &mut Vec<Vec<u8>>, data: Vec<u8>, target: &str) {
    if pending.len() < MAX_PENDING {
        pending.push(data);
    } else {
        warn!("WS proxy: pending queue full for {target}, dropping message");
    }
}
