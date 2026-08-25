//! Asset resolution: everything between a request path and some bytes.
//!
//! Order matters and is not arbitrary — see `resolve`.

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::cache::{CacheStats, CachedFile, FileCache};
use crate::config::Config;
use crate::encoding::{decode_mojibake, js_lowercase, to_mojibake};
use crate::grf::Grf;
use crate::index::{norm_forward, AssetIndex};
use crate::util::{iso_now, safe_join};
use crate::{debug, error, warn};

/// In-memory ring of misses, matching the reference's bounds.
const MAX_MISSING_TRACKED: usize = 1000;
const MISSING_SUMMARY_SIZE: usize = 50;
const NOTIFICATION_COOLDOWN_SECS: u64 = 60;

#[derive(Clone, Serialize)]
pub struct MissingEntry {
    pub timestamp: String,
    #[serde(rename = "requestedPath")]
    pub requested_path: String,
    #[serde(rename = "grfPath")]
    pub grf_path: String,
    #[serde(rename = "mappedPath")]
    pub mapped_path: Option<String>,
}

#[derive(Serialize)]
pub struct MissingSummary {
    pub total: usize,
    pub files: Vec<MissingEntry>,
    #[serde(rename = "logFile")]
    pub log_file: String,
}

#[derive(Serialize)]
pub struct IndexStats {
    #[serde(rename = "totalFiles")]
    pub total_files: usize,
    #[serde(rename = "grfCount")]
    pub grf_count: usize,
    #[serde(rename = "indexBuilt")]
    pub index_built: bool,
    #[serde(rename = "uniqueFiles")]
    pub unique_files: usize,
    #[serde(rename = "mojibakeKeys")]
    pub mojibake_keys: usize,
}

struct Missing {
    seen: HashSet<String>,
    entries: VecDeque<MissingEntry>,
    last_notification: Option<std::time::Instant>,
}

pub struct Client {
    pub cfg: Arc<Config>,
    pub grfs: Vec<Grf>,
    pub index: AssetIndex,
    pub cache: FileCache,
    missing: Mutex<Missing>,
}

/// Where a resolved file came from.  Only used for logging and tests, but it is
/// the first thing anyone asks when an asset is wrong.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Source {
    Cache,
    LocalFile,
    DataOverride,
    Grf(u16),
}

impl Client {
    pub fn new(cfg: Arc<Config>, grfs: Vec<Grf>) -> Client {
        let index = if grfs.is_empty() {
            AssetIndex::empty()
        } else {
            AssetIndex::build(&grfs)
        };
        let cache = FileCache::new(cfg.cache_max_files, cfg.cache_max_memory_mb);

        Client {
            cfg,
            grfs,
            index,
            cache,
            missing: Mutex::new(Missing {
                seen: HashSet::new(),
                entries: VecDeque::new(),
                last_notification: None,
            }),
        }
    }

    fn cache_key(path: &str) -> String {
        js_lowercase(path)
    }

    /// Cache-only lookup, so a conditional request can be answered with the
    /// stored ETag without touching an archive.
    pub fn cached(&self, req_path: &str) -> Option<CachedFile> {
        self.cache.get(&Self::cache_key(req_path))
    }

    /// Resolve a request path to bytes.  Blocking — GRF reads seek into a
    /// multi-gigabyte file and then inflate.
    pub fn resolve(&self, req_path: &str) -> Option<(CachedFile, Source)> {
        let key = Self::cache_key(req_path);

        if let Some(hit) = self.cache.get(&key) {
            return Some((hit, Source::Cache));
        }

        // 2. Loose files shipped beside the server: System/, BGM/, AI/, and
        //    anything auto-extract has already written out.
        if let Some(local) = safe_join(&self.cfg.root, req_path) {
            if local.is_file() {
                match std::fs::read(&local) {
                    Ok(content) => {
                        let file = self.cache.insert(&key, Arc::new(content));
                        return Some((file, Source::LocalFile));
                    }
                    Err(e) => error!("Error reading local file: {e}"),
                }
            }
        }

        // 3. DATA_OVERRIDE_PATH, before the archives: this is how a translation
        //    is applied without repacking 2.4 GB.
        if let Some(override_dir) = &self.cfg.data_override_path {
            let relative = strip_leading_data(req_path);
            if let Some(path) = safe_join(override_dir, relative) {
                if path.is_file() {
                    match std::fs::read(&path) {
                        Ok(content) => {
                            let file = self.cache.insert(&key, Arc::new(content));
                            return Some((file, Source::DataOverride));
                        }
                        Err(e) => error!("Error reading override file: {e}"),
                    }
                }
            }
        }

        // 4./5. The archives, under the requested spelling and then under the
        //       Korean reading of it.
        let mut hit = self.index.lookup(req_path);
        if hit.is_none() {
            let decoded = decode_mojibake(req_path);
            if decoded != req_path {
                hit = self.index.lookup(&decoded);
            }
        }

        if let Some(found) = hit {
            let grf = &self.grfs[found.grf as usize];
            match grf.read_entry(&found.entry) {
                Ok(content) => {
                    let content = Arc::new(content);
                    if self.cfg.client_autoextract {
                        self.extract_file(req_path, Arc::clone(&content));
                    }
                    let file = self.cache.insert(&key, content);
                    return Some((file, Source::Grf(found.grf)));
                }
                Err(e) => {
                    error!(
                        "Error extracting {} from {}: {e}",
                        found.name, grf.file_name
                    );
                }
            }
        }

        self.log_missing(req_path);
        None
    }

    /// Async wrapper: fast path on a cache hit, blocking pool otherwise.
    pub async fn get_file(self: &Arc<Self>, req_path: &str) -> Option<CachedFile> {
        if let Some(hit) = self.cached(req_path) {
            return Some(hit);
        }
        let this = Arc::clone(self);
        let path = req_path.to_string();
        tokio::task::spawn_blocking(move || this.resolve(&path).map(|(f, _)| f))
            .await
            .unwrap_or(None)
    }

    /// Write an extracted asset out beside the server so the next request for
    /// it is answered from disk.
    ///
    /// The write is handed to the blocking pool rather than done inline: the
    /// caller is on the response path, and a client's first load extracts
    /// thousands of files, some of them tens of megabytes.  The reference defers
    /// this the same way, with `setImmediate`.  Without a runtime — a warm-up
    /// pass, a test — it happens inline instead.
    ///
    /// `req_path` comes from an HTTP request, so it is joined defensively; the
    /// reference writes wherever the path points.
    fn extract_file(&self, req_path: &str, content: Arc<Vec<u8>>) {
        let Some(local) = safe_join(&self.cfg.root, req_path) else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || write_extracted(&local, &content));
            }
            Err(_) => write_extracted(&local, &content),
        }
    }

    fn log_missing(&self, req_path: &str) {
        let grf_path = req_path.replace('/', "\\");
        let entry = {
            let mut missing = self.missing.lock().unwrap();
            if !missing.seen.insert(req_path.to_string()) {
                return;
            }

            let entry = MissingEntry {
                timestamp: iso_now(),
                requested_path: req_path.to_string(),
                grf_path: grf_path.clone(),
                mapped_path: None,
            };
            missing.entries.push_back(entry.clone());
            if missing.entries.len() > MAX_MISSING_TRACKED {
                missing.entries.pop_front();
            }

            let should_notify = missing.entries.len() >= 10
                && missing
                    .last_notification
                    .map(|t| t.elapsed().as_secs() >= NOTIFICATION_COOLDOWN_SECS)
                    .unwrap_or(true);
            if should_notify {
                missing.last_notification = Some(std::time::Instant::now());
                let total = missing.entries.len();
                let log = self.cfg.missing_files_log();
                warn!(
                    "MISSING FILES ALERT: {total} files not found. Log: {}",
                    log.display()
                );
            }

            entry
        };

        debug!("File not found: {grf_path}");
        self.append_missing_log(&entry);
    }

    fn append_missing_log(&self, entry: &MissingEntry) {
        let dir = self.cfg.logs_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let line = match serde_json::to_string(entry) {
            Ok(s) => s,
            Err(_) => return,
        };
        let path = self.cfg.missing_files_log();
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{line}");
            }
            Err(e) => error!("Failed to write missing file log: {e}"),
        }
    }

    pub fn missing_summary(&self) -> MissingSummary {
        let missing = self.missing.lock().unwrap();
        let total = missing.entries.len();
        let start = total.saturating_sub(MISSING_SUMMARY_SIZE);
        MissingSummary {
            total,
            files: missing.entries.iter().skip(start).cloned().collect(),
            log_file: self.cfg.missing_files_log().to_string_lossy().into_owned(),
        }
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    pub fn index_stats(&self) -> IndexStats {
        IndexStats {
            total_files: self.index.key_count(),
            grf_count: self.grfs.len(),
            index_built: true,
            unique_files: self.index.reachable_count(),
            mojibake_keys: self.index.mojibake_key_count,
        }
    }

    pub fn list_files(&self) -> Vec<&str> {
        self.index.names().collect()
    }

    pub fn search(&self, re: &regex_lite::Regex) -> Vec<&str> {
        self.index.names().filter(|n| re.is_match(n)).collect()
    }

    /// Preload assets the client always asks for.  Entries are stored under the
    /// key the browser will actually request — the mojibake spelling with
    /// forward slashes — so a warm cache is a cache that hits.
    pub fn warm_cache(&self, limit: usize) -> usize {
        let patterns = warm_up_patterns();
        let mut warmed = 0usize;

        for file in self.index.reachable_files() {
            if warmed >= limit {
                break;
            }
            if !patterns.iter().any(|p| p.is_match(&file.name)) {
                continue;
            }
            let grf = &self.grfs[file.grf as usize];
            let Ok(content) = grf.read_entry(&file.entry) else {
                continue;
            };
            let key = norm_forward(&to_mojibake(&file.name));
            self.cache.insert(&key, Arc::new(content));
            warmed += 1;
        }

        warmed
    }
}

fn write_extracted(path: &std::path::Path, content: &[u8]) {
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            error!("Failed to create {}: {e}", dir.display());
            return;
        }
    }
    if let Err(e) = std::fs::write(path, content) {
        error!("Failed to extract {}: {e}", path.display());
    }
}

/// `DATA_OVERRIDE_PATH` points at a client's `data/` directory, so the request's
/// own `data/` prefix has to come off first.
fn strip_leading_data(path: &str) -> &str {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("data/") || lower.starts_with("data\\") {
        &path[5..]
    } else {
        path
    }
}

fn warm_up_patterns() -> Vec<regex_lite::Regex> {
    // Mirrors the reference's default list: interface textures, the default
    // spawn map, every map's altitude/world data, player sprites, palettes and
    // the small Lua configuration files loaded during boot.
    const PATTERNS: [&str; 12] = [
        r"(?i)data.texture.유저인터페이스",
        r"(?i)data.texture.userinterface",
        r"(?i)loading.",
        r"(?i)cardbmp.",
        r"(?i)prontera\.gat$",
        r"(?i)prontera\.gnd$",
        r"(?i)prontera\.rsw$",
        r"(?i)\.gat$",
        r"(?i)\.rsw$",
        r"(?i)data.sprite.인간족",
        r"(?i)\.pal$",
        r"(?i)\.lub$",
    ];
    PATTERNS
        .iter()
        .filter_map(|p| regex_lite::Regex::new(p).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_prefix_is_stripped_for_the_override_directory() {
        assert_eq!(strip_leading_data("data/foo/bar.txt"), "foo/bar.txt");
        assert_eq!(strip_leading_data("DATA\\foo.txt"), "foo.txt");
        assert_eq!(strip_leading_data("BGM/01.mp3"), "BGM/01.mp3");
        assert_eq!(strip_leading_data("database/x.txt"), "database/x.txt");
    }

    #[test]
    fn warm_up_patterns_all_compile() {
        assert_eq!(warm_up_patterns().len(), 12);
    }
}
