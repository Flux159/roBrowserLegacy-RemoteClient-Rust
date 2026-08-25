//! WebSocket-to-TCP proxy, against a stand-in for rAthena.

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use support::{client_for, config_for, write_data_ini, GrfBuilder, TempDir, TestServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

/// `CA_LOGIN`: u16 packet id, u32 version, char[24] user, char[24] pass, u8
/// client type.  55 bytes, and the first thing a real client ever sends.
fn ca_login(user: &str, pass: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(55);
    packet.extend_from_slice(&0x0064u16.to_le_bytes());
    packet.extend_from_slice(&20180621u32.to_le_bytes());
    let mut field = [0u8; 24];
    field[..user.len()].copy_from_slice(user.as_bytes());
    packet.extend_from_slice(&field);
    let mut field = [0u8; 24];
    field[..pass.len()].copy_from_slice(pass.as_bytes());
    packet.extend_from_slice(&field);
    packet.push(0x01);
    assert_eq!(packet.len(), 55);
    packet
}

/// A minimal `AC_ACCEPT_LOGIN` (0x0ac4): id, length, and enough filler to look
/// like the real thing.
fn ac_accept_login() -> Vec<u8> {
    let mut packet = vec![0u8; 160];
    packet[0..2].copy_from_slice(&0x0ac4u16.to_le_bytes());
    packet[2..4].copy_from_slice(&160u16.to_le_bytes());
    packet[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    packet
}

/// A fake login server: replies to `CA_LOGIN` and then echoes whatever it is
/// sent, so a test can check the stream stays byte-exact under traffic.
async fn fake_rathena() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            socket.set_nodelay(true).unwrap();
            tokio::spawn(async move {
                let mut login = [0u8; 55];
                if socket.read_exact(&mut login).await.is_err() {
                    return;
                }
                if u16::from_le_bytes([login[0], login[1]]) != 0x0064 {
                    return;
                }
                if socket.write_all(&ac_accept_login()).await.is_err() {
                    return;
                }
                let mut buffer = vec![0u8; 8192];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    (addr, handle)
}

async fn proxy_server(allowed: &str) -> (TempDir, TestServer) {
    let dir = TempDir::new("ws");
    GrfBuilder::new()
        .file("data\\x.txt", b"x")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let overrides = [("ENABLE_WSPROXY", "true"), ("WS_ALLOWED_TARGETS", allowed)];
    let client = client_for(&dir.path, &overrides);
    let cfg = config_for(&dir.path, &overrides);
    let server = TestServer::start(cfg, client, json!({})).await;
    (dir, server)
}

async fn open_ws(
    server: &TestServer,
    target: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
    let url = format!("ws://{}/ws/{}", server.addr, target);
    let (stream, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    stream
}

#[tokio::test]
async fn a_real_login_handshake_passes_through_byte_for_byte() {
    let (game, _game_handle) = fake_rathena().await;
    let target = game.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;
    ws.send(Message::Binary(ca_login("test", "secret").into()))
        .await
        .unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for AC_ACCEPT_LOGIN")
        .unwrap()
        .unwrap();

    let bytes = reply.into_data().to_vec();
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x0ac4);
    assert_eq!(bytes, ac_accept_login());
}

#[tokio::test]
async fn a_target_outside_the_allowlist_is_closed_not_connected() {
    let (game, _game_handle) = fake_rathena().await;
    // The allowlist names a different port than the one we will ask for.
    let (_dir, server) = proxy_server("127.0.0.1:1").await;

    let mut ws = open_ws(&server, &game.to_string()).await;
    ws.send(Message::Binary(ca_login("test", "secret").into()))
        .await
        .unwrap();

    // The socket closes without ever forwarding anything.
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        match ws.next().await {
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => true,
            Some(Ok(_)) => false,
        }
    })
    .await
    .expect("timed out");

    assert!(outcome, "proxy forwarded to a target that is not allowed");
}

#[tokio::test]
async fn a_malformed_target_is_closed() {
    let (_dir, server) = proxy_server("127.0.0.1:6900").await;

    let mut ws = open_ws(&server, "not-a-target").await;
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        match ws.next().await {
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => true,
            Some(Ok(_)) => false,
        }
    })
    .await
    .expect("timed out");

    assert!(closed);
}

/// roBrowser sends its first packets synchronously from `onopen`, before the
/// proxy's TCP connect has finished.  Those frames must be buffered and
/// flushed, not dropped.
#[tokio::test]
async fn frames_sent_immediately_after_the_upgrade_are_not_dropped() {
    let (game, _game_handle) = fake_rathena().await;
    let target = game.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;

    // The login packet plus a burst that lands in the same tick.
    ws.send(Message::Binary(ca_login("test", "secret").into()))
        .await
        .unwrap();
    let mut expected_echo = Vec::new();
    for i in 0u16..32 {
        let payload = vec![i as u8; 64];
        expected_echo.extend_from_slice(&payload);
        ws.send(Message::Binary(payload.into())).await.unwrap();
    }

    let mut received = Vec::new();
    let want = ac_accept_login().len() + expected_echo.len();
    tokio::time::timeout(Duration::from_secs(10), async {
        while received.len() < want {
            let message = ws.next().await.unwrap().unwrap();
            received.extend_from_slice(&message.into_data());
        }
    })
    .await
    .expect("timed out waiting for the buffered burst");

    let mut want_bytes = ac_accept_login();
    want_bytes.extend_from_slice(&expected_echo);
    assert_eq!(received, want_bytes);
}

#[tokio::test]
async fn the_stream_stays_intact_under_sustained_traffic() {
    let (game, _game_handle) = fake_rathena().await;
    let target = game.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;
    ws.send(Message::Binary(ca_login("test", "secret").into()))
        .await
        .unwrap();

    // Drain the login reply.
    let mut received = Vec::new();
    while received.len() < ac_accept_login().len() {
        let message = ws.next().await.unwrap().unwrap();
        received.extend_from_slice(&message.into_data());
    }

    // Every byte value, in packets of the size RO actually uses, for long
    // enough that a proxy that works briefly and then dies would be caught.
    let mut sent = Vec::new();
    for round in 0..500u32 {
        let size = 2 + (round as usize % 60);
        let payload: Vec<u8> = (0..size)
            .map(|i| ((round as usize + i) % 256) as u8)
            .collect();
        sent.extend_from_slice(&payload);
        ws.send(Message::Binary(payload.into())).await.unwrap();
    }

    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while echoed.len() < sent.len() {
            let message = ws.next().await.unwrap().unwrap();
            echoed.extend_from_slice(&message.into_data());
        }
    })
    .await
    .expect("timed out draining sustained traffic");

    assert_eq!(echoed, sent);
}

#[tokio::test]
async fn the_game_server_closing_tears_down_the_websocket() {
    // A listener that accepts and immediately hangs up.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });

    let target = addr.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;
    ws.send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = ws.next().await {
            if matches!(message, Ok(Message::Close(_)) | Err(_)) {
                return true;
            }
        }
        true
    })
    .await
    .expect("the websocket outlived the TCP connection");

    assert!(closed);
}

#[tokio::test]
async fn a_refused_tcp_connection_closes_the_websocket() {
    // Bind and drop, so the port is almost certainly closed.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let target = addr.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = ws.next().await {
            if matches!(message, Ok(Message::Close(_)) | Err(_)) {
                return true;
            }
        }
        true
    })
    .await
    .expect("timed out");

    assert!(closed);
}

#[tokio::test]
async fn the_client_closing_tears_down_the_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 1024];
        // Read until EOF, which is what a torn-down proxy produces.
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = tx.send(());
    });

    let target = addr.to_string();
    let (_dir, server) = proxy_server(&target).await;

    let mut ws = open_ws(&server, &target).await;
    ws.send(Message::Binary(vec![9, 9, 9].into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ws.close(None).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the TCP connection outlived the websocket")
        .unwrap();
}

#[tokio::test]
async fn the_proxy_route_is_absent_when_the_proxy_is_disabled() {
    let dir = TempDir::new("ws-off");
    GrfBuilder::new()
        .file("data\\x.txt", b"x")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let client = client_for(&dir.path, &[]);
    let cfg = config_for(&dir.path, &[]);
    let server = TestServer::start(cfg, client, json!({})).await;

    let url = format!("ws://{}/ws/127.0.0.1:6900", server.addr);
    assert!(tokio_tungstenite::connect_async(url).await.is_err());
}
