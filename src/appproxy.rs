//! A path prefix handed to a loopback HTTP service: the app's own endpoints,
//! reached by players who load the game from this server.
//!
//! The application that runs this server sometimes has a small HTTP endpoint
//! of its own that the game page must reach *on this origin* -- so its cookies
//! are this origin's and same-origin checks hold -- for players on other
//! machines. Off unless both are set:
//!
//!   APP_PROXY_PREFIX   a path prefix, e.g. `/_friend/remember/`
//!   APP_PROXY_TARGET   `127.0.0.1:<port>` (loopback only)
//!
//! Only POST, with a body of at most 4 KiB, is forwarded. The request goes out
//! with its path, the original Host, Origin, Cookie and Content-Type, and an
//! `X-Forwarded-For` naming the peer this server saw (one supplied by the
//! client is dropped). The answer comes back with its status, Content-Type,
//! Cache-Control and Set-Cookie headers and at most 64 KiB of body, and
//! nothing else -- no redirects are followed. A target that does not answer
//! within five seconds is a 502.
//!
//! The same forwarding carries guild emblems to rAthena's web-server, which
//! keeps them: the client posts to `/emblem/upload` and `/emblem/download` on
//! the origin it was loaded from. Off unless set:
//!
//!   WEB_SERVER_TARGET  `127.0.0.1:<port>` of the web-server (loopback only)
//!
//! Only those two paths go there, and up to 64 KiB of request, since an emblem
//! may be 50 KB (src/web/emblem_controller.cpp, MAX_EMBLEM_SIZE).

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::routes::AppState;
use crate::warn;

pub const MAX_REQUEST_BODY: usize = 4 * 1024;
pub const MAX_WEB_SERVER_REQUEST_BODY: usize = 64 * 1024;
/// What rAthena's web-server answers that the client asks for.
pub const WEB_SERVER_ROUTES: [&str; 2] = ["/emblem/upload", "/emblem/download"];
pub const MAX_RESPONSE: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

/// A prefix this server will hand on: starts and ends with `/`, at least one
/// segment between, letters, digits, `_` and `-` only, and never one of the
/// paths this server answers itself.
pub fn valid_prefix(prefix: &str) -> bool {
    prefix.len() >= 3
        && prefix.len() <= 64
        && prefix.starts_with('/')
        && prefix.ends_with('/')
        && !prefix.contains("//")
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'-')
        && !["/api/", "/ws/", "/batch/", "/search/", "/list-files/"]
            .iter()
            .any(|own| prefix.starts_with(own))
}

/// Loopback only: this is a way into the host's own app, never an open proxy.
pub fn valid_target(target: &str) -> bool {
    match crate::config::parse_target(target) {
        Some((host, _)) => host == "127.0.0.1" || host == "[::1]" || host == "localhost",
        None => false,
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// One header line, or nothing if the value could split the request.
fn line(name: &str, value: &str) -> String {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return String::new();
    }
    format!("{name}: {value}\r\n")
}

pub async fn forward(State(state): State<AppState>, request: Request) -> Response {
    let Some((prefix, target)) = state.cfg.app_proxy.clone() else {
        return crate::http::not_found();
    };
    relay(
        request,
        &target,
        |path| path.starts_with(&prefix),
        MAX_REQUEST_BODY,
        "The app",
    )
    .await
}

/// Guild emblems, to and from rAthena's web-server.
pub async fn forward_web_server(State(state): State<AppState>, request: Request) -> Response {
    let Some(target) = state.cfg.web_server_proxy.clone() else {
        return crate::http::not_found();
    };
    relay(
        request,
        &target,
        |path| WEB_SERVER_ROUTES.contains(&path),
        MAX_WEB_SERVER_REQUEST_BODY,
        "The web server",
    )
    .await
}

/// POST `request` on to `target`, if `allowed` takes its path, with at most
/// `max_body` bytes of body. `who` names the target in a 502.
async fn relay(
    request: Request,
    target: &str,
    allowed: impl Fn(&str) -> bool,
    max_body: usize,
    who: &str,
) -> Response {
    if request.method() != Method::POST {
        return crate::http::text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    if !allowed(&path) || path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return crate::http::not_found();
    }
    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), max_body).await {
        Ok(body) => body,
        Err(_) => return crate::http::text(StatusCode::PAYLOAD_TOO_LARGE, "Request too large"),
    };

    let mut head = format!(
        "POST {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    head += &line("Host", header(&headers, "host").unwrap_or(""));
    for name in ["origin", "cookie", "content-type"] {
        if let Some(value) = header(&headers, name) {
            head += &line(name, value);
        }
    }
    head += &line("X-Forwarded-For", &peer);
    head += "\r\n";

    let exchange = async {
        let mut stream = TcpStream::connect(target).await?;
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&body).await?;
        let mut answer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&chunk[..n]);
            if answer.len() > MAX_RESPONSE {
                return Err(std::io::Error::other("response too large"));
            }
        }
        Ok::<_, std::io::Error>(answer)
    };
    let answer = match tokio::time::timeout(TIMEOUT, exchange).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => {
            warn!("Proxy to {target} failed: {e}");
            return crate::http::text(StatusCode::BAD_GATEWAY, format!("{who} did not answer"));
        }
        Err(_) => {
            return crate::http::text(StatusCode::BAD_GATEWAY, format!("{who} did not answer"))
        }
    };
    parse_response(&answer).unwrap_or_else(|| {
        crate::http::text(
            StatusCode::BAD_GATEWAY,
            format!("{who} gave an unreadable answer"),
        )
    })
}

/// An HTTP/1.x answer with a Content-Length (or read to close), reduced to the
/// headers a page needs. Redirects are not passed on.
pub fn parse_response(raw: &[u8]) -> Option<Response> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = StatusCode::from_u16(parts.next()?.parse().ok()?).ok()?;
    if status.is_redirection() || status.is_informational() {
        return None;
    }
    let mut body = raw[end + 4..].to_vec();
    let mut response = Response::builder().status(status);
    for header_line in lines {
        let Some((name, value)) = header_line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        match name.as_str() {
            "content-type" | "cache-control" | "set-cookie" => {
                response = response.header(name, HeaderValue::from_str(value).ok()?);
            }
            "content-length" => {
                let length: usize = value.parse().ok()?;
                if length > body.len() {
                    return None;
                }
                body.truncate(length);
            }
            "transfer-encoding" => return None,
            _ => {}
        }
    }
    response
        .header("x-content-type-options", "nosniff")
        .body(Body::from(body))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tidy_prefixes_that_are_not_ours() {
        assert!(valid_prefix("/_friend/remember/"));
        assert!(valid_prefix("/_app/"));
        for bad in [
            "", "/", "_app/", "/_app", "/a b/", "/../", "//x/", "/api/x/", "/ws/", "/%2e/",
        ] {
            assert!(!valid_prefix(bad), "{bad}");
        }
    }

    #[test]
    fn only_loopback_targets() {
        assert!(valid_target("127.0.0.1:3341"));
        assert!(valid_target("localhost:9"));
        assert!(!valid_target("192.168.1.2:3341"));
        assert!(!valid_target("example.com:80"));
        assert!(!valid_target("127.0.0.1"));
    }

    #[test]
    fn answers_keep_only_what_a_page_needs() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: a=b; HttpOnly\r\nX-Secret: no\r\nContent-Length: 2\r\n\r\n{}junk";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["set-cookie"], "a=b; HttpOnly");
        assert!(response.headers().get("x-secret").is_none());
        assert!(parse_response(b"HTTP/1.1 302 Found\r\nLocation: http://evil/\r\n\r\n").is_none());
        assert!(parse_response(b"garbage").is_none());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").is_none());
    }

    #[test]
    fn header_values_cannot_split_the_request() {
        assert_eq!(line("Cookie", "a=b\r\nX-Evil: 1"), "");
        assert_eq!(line("Cookie", "a=b"), "Cookie: a=b\r\n");
    }
}
