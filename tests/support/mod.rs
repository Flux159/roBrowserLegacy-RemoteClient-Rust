//! Test support: a minimal GRF writer, an in-process server harness and a
//! blunt HTTP client.
//!
//! The GRF writer exists because the interesting parser bugs — the mojibake
//! index, the 0x300 layout, DES entries — cannot be exercised without a real
//! archive, and a real archive is 4 GB of somebody else's copyright.

#![allow(dead_code)]

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use robrowser_remoteclient::client::Client;
use robrowser_remoteclient::config::Config;
use robrowser_remoteclient::grf::Grf;
use robrowser_remoteclient::http::Cors;
use robrowser_remoteclient::routes::{router, AppState};
use serde_json::Value;

pub const FILELIST_TYPE_FILE: u8 = 0x01;
pub const FILELIST_TYPE_ENCRYPT_MIXED: u8 = 0x02;
pub const FILELIST_TYPE_ENCRYPT_HEADER: u8 = 0x04;

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub struct Entry {
    /// Raw name bytes, exactly as they will sit in the file table.
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u8,
    /// Store the bytes uncompressed (`real_size == compressed_size`).
    pub stored: bool,
}

#[derive(Default)]
pub struct GrfBuilder {
    entries: Vec<Entry>,
}

impl GrfBuilder {
    pub fn new() -> GrfBuilder {
        GrfBuilder::default()
    }

    /// Add a file whose name is CP949-encoded from `name`.
    pub fn file(mut self, name: &str, data: &[u8]) -> Self {
        self.entries.push(Entry {
            name: robrowser_remoteclient::encoding::cp949_encode(name),
            data: data.to_vec(),
            flags: FILELIST_TYPE_FILE,
            stored: false,
        });
        self
    }

    /// Add a file stored without compression.
    pub fn stored_file(mut self, name: &str, data: &[u8]) -> Self {
        self.entries.push(Entry {
            name: robrowser_remoteclient::encoding::cp949_encode(name),
            data: data.to_vec(),
            flags: FILELIST_TYPE_FILE,
            stored: true,
        });
        self
    }

    /// Add a DES-encrypted file.  `mixed` selects encryption mode 0 (DES on
    /// the leading blocks plus a periodic mix of DES and byte-shuffled blocks)
    /// rather than mode 1 (DES on the leading blocks only).
    pub fn encrypted_file(mut self, name: &str, data: &[u8], mixed: bool) -> Self {
        self.entries.push(Entry {
            name: robrowser_remoteclient::encoding::cp949_encode(name),
            data: data.to_vec(),
            flags: FILELIST_TYPE_FILE
                | if mixed {
                    FILELIST_TYPE_ENCRYPT_MIXED
                } else {
                    FILELIST_TYPE_ENCRYPT_HEADER
                },
            stored: false,
        });
        self
    }

    /// Add a non-file entry, which the parser must skip.
    pub fn directory(mut self, name: &str) -> Self {
        self.entries.push(Entry {
            name: robrowser_remoteclient::encoding::cp949_encode(name),
            data: Vec::new(),
            flags: 0,
            stored: true,
        });
        self
    }

    pub fn write_v200(&self, path: &Path) {
        self.write(path, 0x200);
    }

    pub fn write_v300(&self, path: &Path) {
        self.write(path, 0x300);
    }

    /// A 0x300 archive signed the way GRF Editor signs them.
    ///
    /// The signature is shorter than the 15-byte field, and the bytes after
    /// its terminator are not padding -- real archives carry data there, so
    /// this writes some to keep the test honest about what has to be ignored.
    pub fn write_v300_event_horizon(&self, path: &Path) {
        self.write_signed(path, 0x300, b"Event Horizon\0c\0");
    }

    fn write(&self, path: &Path, version: u32) {
        self.write_signed(path, version, b"Master of Magic");
    }

    fn write_signed(&self, path: &Path, version: u32, signature: &[u8]) {
        let mut body: Vec<u8> = Vec::new();
        let mut table: Vec<u8> = Vec::new();

        for entry in &self.entries {
            let mut payload = if entry.stored {
                entry.data.clone()
            } else {
                deflate(&entry.data)
            };
            let offset = body.len() as u64;
            let compressed_size = payload.len() as u32;
            let real_size = if entry.stored {
                compressed_size
            } else {
                entry.data.len() as u32
            };

            // DES works in whole 8-byte blocks, so an encrypted entry is padded
            // out and `length_aligned` records the padded length.
            let mut length_aligned = compressed_size;
            let encrypted =
                entry.flags & (FILELIST_TYPE_ENCRYPT_MIXED | FILELIST_TYPE_ENCRYPT_HEADER) != 0;
            if encrypted {
                length_aligned = (compressed_size + 7) & !7;
                payload.resize(length_aligned as usize, 0);
                if entry.flags & FILELIST_TYPE_ENCRYPT_MIXED != 0 {
                    robrowser_remoteclient::des::encode_full(
                        &mut payload,
                        length_aligned as usize,
                        compressed_size,
                    );
                } else {
                    robrowser_remoteclient::des::encode_header(
                        &mut payload,
                        length_aligned as usize,
                    );
                }
            }

            body.extend_from_slice(&payload);

            table.extend_from_slice(&entry.name);
            table.push(0);
            table.extend_from_slice(&compressed_size.to_le_bytes());
            table.extend_from_slice(&length_aligned.to_le_bytes());
            table.extend_from_slice(&real_size.to_le_bytes());
            table.push(entry.flags);
            if version == 0x300 {
                table.extend_from_slice(&offset.to_le_bytes());
            } else {
                table.extend_from_slice(&(offset as u32).to_le_bytes());
            }
        }

        let compressed_table = deflate(&table);

        let mut header = vec![0u8; 46];
        header[0..signature.len()].copy_from_slice(signature);
        let table_offset = body.len() as u64;

        if version == 0x300 {
            header[30..34].copy_from_slice(&(table_offset as u32).to_le_bytes());
            header[34..38].copy_from_slice(&((table_offset >> 32) as u32).to_le_bytes());
            header[38..42].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        } else {
            header[30..34].copy_from_slice(&(table_offset as u32).to_le_bytes());
            header[34..38].copy_from_slice(&0u32.to_le_bytes()); // seed
            header[38..42].copy_from_slice(&(self.entries.len() as u32 + 7).to_le_bytes());
        }
        header[42..46].copy_from_slice(&version.to_le_bytes());

        let mut out = header;
        out.extend_from_slice(&body);
        // 0x300 keeps a spare 32-bit field in front of the table header.
        if version == 0x300 {
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out.extend_from_slice(&(compressed_table.len() as u32).to_le_bytes());
        out.extend_from_slice(&(table.len() as u32).to_le_bytes());
        out.extend_from_slice(&compressed_table);

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(path, out).unwrap();
    }
}

/// A scratch directory that removes itself.
pub struct TempDir {
    pub path: std::path::PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        // A counter, not just a clock: the system clock's resolution is coarse
        // enough that two threads starting together get the same reading and
        // then quietly share a directory.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(format!("robrowser-rs-test-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    pub fn join(&self, rel: &str) -> std::path::PathBuf {
        self.path.join(rel)
    }

    pub fn write(&self, rel: &str, content: &[u8]) {
        let target = self.path.join(rel);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Write a DATA.INI listing the given archives, in order.
pub fn write_data_ini(root: &Path, grfs: &[&str]) {
    let resources = root.join("resources");
    std::fs::create_dir_all(&resources).unwrap();
    let mut content = String::from("[Data]\n");
    for (i, name) in grfs.iter().enumerate() {
        content.push_str(&format!("{i}={name}\n"));
    }
    std::fs::write(resources.join("DATA.INI"), content).unwrap();
}

/// Build a `Client` over the archives in `<root>/resources`, honouring
/// DATA.INI order.
pub fn client_for(root: &Path, overrides: &[(&str, &str)]) -> Arc<Client> {
    let cfg = config_for(root, overrides);
    let ini = std::fs::read_to_string(cfg.data_ini_path()).unwrap();
    let grfs: Vec<Grf> = robrowser_remoteclient::config::parse_data_ini(&ini)
        .iter()
        .map(|name| Grf::open(&cfg.resources_dir().join(name)).unwrap())
        .collect();
    Arc::new(Client::new(Arc::new(cfg), grfs))
}

/// Build a `Config` for `root`, with the given environment overrides applied
/// for the duration of the call.
pub fn config_for(root: &Path, overrides: &[(&str, &str)]) -> Config {
    // Serialised because `Config::from_env` reads the process environment.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let managed = [
        "SERVER_ROOT",
        "PORT",
        "CLIENT_PUBLIC_URL",
        "NODE_ENV",
        "ENABLE_STATIC_SERVE",
        "ENABLE_WSPROXY",
        "ENABLE_COMPRESSION",
        "ROBROWSER_PATH",
        "WS_ALLOWED_TARGETS",
        "DATA_OVERRIDE_PATH",
        "CACHE_MAX_FILES",
        "CACHE_MAX_MEMORY_MB",
        "CACHE_WARM_UP",
        "CACHE_WARM_UP_LIMIT",
        "CLIENT_RESPATH",
        "CLIENT_DATAINI",
        "CLIENT_ENABLESEARCH",
        "CLIENT_AUTOEXTRACT",
        "GRF_FILENAME_ENCODING",
    ];
    for key in managed {
        std::env::remove_var(key);
    }

    std::env::set_var("SERVER_ROOT", root);
    std::env::set_var("CLIENT_PUBLIC_URL", "http://127.0.0.1:8000");
    for (key, value) in overrides {
        std::env::set_var(key, value);
    }

    let cfg = Config::from_env();
    for key in managed {
        std::env::remove_var(key);
    }
    cfg
}

/// A router bound to an ephemeral port, serving in the background.
pub struct TestServer {
    pub addr: SocketAddr,
    pub client: Arc<Client>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    pub async fn start(cfg: Config, client: Arc<Client>, health: Value) -> TestServer {
        let cfg = Arc::new(cfg);
        let state = AppState {
            cfg: Arc::clone(&cfg),
            client: Arc::clone(&client),
            cors: Arc::new(Cors::new(cfg.client_public_url.as_deref())),
            health: Arc::new(health),
        };
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestServer {
            addr,
            client,
            handle,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response was not JSON")
    }
}

/// A deliberately blunt HTTP/1.1 client: it sends the request line verbatim, so
/// a test can send a path the URL crate would have "helpfully" re-encoded.
pub async fn request(
    addr: SocketAddr,
    method: &str,
    raw_path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request =
        format!("{method} {raw_path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await.unwrap();
    if let Some(body) = body {
        stream.write_all(body).await.unwrap();
    }
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator in response");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body = if is_chunked { dechunk(&body) } else { body };

    let gzipped = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v.contains("gzip"));
    let body = if gzipped { gunzip(&body) } else { body };

    HttpResponse {
        status,
        headers,
        body,
    }
}

pub fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(eol) = data[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&data[pos..pos + eol]).into_owned();
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        pos += eol + 2;
        if size == 0 {
            break;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
    out
}
