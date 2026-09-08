//! Exercise the shipped binary's parent protocol, not an in-process substitute.
mod support;

use robrowser_remoteclient::managed::{
    sign, verify, Bootstrap, Envelope, Identity, Request, READY_PREFIX,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;
use support::{write_data_ini, GrfBuilder, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

struct Running {
    _dir: TempDir,
    child: Child,
    input: ChildStdin,
    identity: Identity,
}

async fn start() -> Running {
    let dir = TempDir::new("managed");
    GrfBuilder::new()
        .file("data/test.txt", b"real archive bytes")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let environment: BTreeMap<String, String> = [
        (
            "SERVER_ROOT".into(),
            dir.path.to_string_lossy().into_owned(),
        ),
        ("PORT".into(), port.to_string()),
        ("HOST".into(), "127.0.0.1".into()),
        (
            "CLIENT_PUBLIC_URL".into(),
            format!("http://127.0.0.1:{port}"),
        ),
        ("NODE_ENV".into(), "production".into()),
    ]
    .into_iter()
    .collect();
    let mut child = Command::new(env!("CARGO_BIN_EXE_robrowser-remoteclient"))
        .arg("--managed")
        // Windows needs SystemRoot to load Winsock providers. Keep the OS
        // environment while overriding every setting relevant to this fixture.
        .envs(&environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let bootstrap = json!({ "secret": "ab".repeat(32), "launchId": "cd".repeat(32),
        "stateRoot": dir.path, "environment": environment });
    input
        .write_all(format!("{bootstrap}\n").as_bytes())
        .await
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let identity = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            assert!(
                output.read_line(&mut line).await.unwrap() > 0,
                "server exited before ready"
            );
            if let Some(value) = line.strip_prefix(READY_PREFIX) {
                break serde_json::from_str::<Identity>(value).unwrap();
            }
        }
    })
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut output, &mut tokio::io::sink()).await;
    });
    assert_eq!(identity.pid, child.id().unwrap());
    assert_eq!(identity.protocol, 1);
    assert_eq!(identity.http_port, port);
    Running {
        _dir: dir,
        child,
        input,
        identity,
    }
}

async fn send(identity: &Identity, request: &Request, secret: &[u8]) -> Vec<u8> {
    let message =
        serde_json::to_string(&sign(secret, serde_json::to_string(request).unwrap())).unwrap();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", identity.control_port))
        .await
        .unwrap();
    socket
        .write_all(format!("{message}\n").as_bytes())
        .await
        .unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    output
}

fn request(id: &Identity, action: &str) -> Request {
    Request {
        launch_id: id.launch_id.clone(),
        challenge: "ef".repeat(32),
        action: action.into(),
    }
}

#[tokio::test]
async fn status_is_authenticated_and_shutdown_requires_the_same_launch() {
    let mut running = start().await;
    let id = &running.identity;
    let status = send(id, &request(id, "status"), &[0xab; 32]).await;
    let envelope: Envelope = serde_json::from_slice(&status).unwrap();
    assert!(verify(&[0xab; 32], &envelope));
    let body: serde_json::Value = serde_json::from_str(&envelope.payload).unwrap();
    assert_eq!(body["identity"], serde_json::to_value(id).unwrap());
    assert_eq!(body["challenge"], "ef".repeat(32));

    assert!(send(id, &request(id, "shutdown"), &[0xac; 32])
        .await
        .is_empty());
    let mut stale = request(id, "shutdown");
    stale.launch_id = "00".repeat(32);
    assert!(send(id, &stale, &[0xab; 32]).await.is_empty());
    assert!(running.child.try_wait().unwrap().is_none());

    let reply = send(id, &request(id, "shutdown"), &[0xab; 32]).await;
    assert!(!reply.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_secs(7), running.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn parent_pipe_eof_exits_the_process() {
    let mut running = start().await;
    drop(running.input);
    assert!(
        tokio::time::timeout(Duration::from_secs(7), running.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn control_rejects_oversized_messages_and_stays_available() {
    let mut running = start().await;
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", running.identity.control_port))
        .await
        .unwrap();
    socket.write_all(&vec![b'x'; 17000]).await.unwrap();
    let mut output = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut output))
        .await
        .unwrap();
    assert!(output.is_empty());
    assert!(!send(
        &running.identity,
        &request(&running.identity, "status"),
        &[0xab; 32]
    )
    .await
    .is_empty());
    drop(running.input);
    tokio::time::timeout(Duration::from_secs(7), running.child.wait())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_bootstrap_fails_without_announcing_readiness() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_robrowser-remoteclient"))
        .arg("--managed")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"secret\":\"too short\"}\n")
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(READY_PREFIX));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("too short"));
}

#[test]
fn bootstrap_schema_rejects_unrecognized_fields() {
    assert!(serde_json::from_value::<Bootstrap>(json!({
        "secret": "ab".repeat(32), "launchId": "cd".repeat(32),
        "stateRoot": "/tmp", "environment": {}, "shutdown": true,
    }))
    .is_err());
}
