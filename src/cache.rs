//! LRU file cache, bounded by entry count *and* by bytes.
//!
//! Two details carried over from the reference because they matter: an entry
//! larger than 10% of the memory budget is never cached (one 40 MB map file
//! should not evict the entire UI), and eviction continues until both limits
//! are satisfied rather than stopping at the first.
//!
//! The ETag is computed once, when the entry is stored, and handed back with
//! the bytes.  Hashing 5 MB of sprite on every conditional request is the kind
//! of cost that only shows up under load.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};

#[derive(Clone)]
pub struct CachedFile {
    pub data: Arc<Vec<u8>>,
    pub etag: Arc<str>,
}

struct Entry {
    data: Arc<Vec<u8>>,
    etag: Arc<str>,
    size: usize,
    seq: u64,
}

struct Inner {
    map: HashMap<String, Entry>,
    /// Access order, oldest first.  `seq` is unique and monotonic, so this is
    /// a total order and eviction is just "take the front".
    order: BTreeMap<u64, String>,
    current_memory: usize,
    next_seq: u64,
}

pub struct FileCache {
    inner: Mutex<Inner>,
    max_size: usize,
    max_memory_bytes: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// First 16 hex characters of the MD5 of the content, as the reference and the
/// specification both call for.
pub fn compute_etag(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Md5::digest(data);
    let mut s = String::with_capacity(16);
    for byte in &digest[..8] {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

impl FileCache {
    pub fn new(max_size: usize, max_memory_mb: usize) -> FileCache {
        FileCache {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: BTreeMap::new(),
                current_memory: 0,
                next_seq: 0,
            }),
            max_size,
            max_memory_bytes: max_memory_mb * 1024 * 1024,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedFile> {
        let mut inner = self.inner.lock().unwrap();
        let seq = inner.next_seq;
        let Some(entry) = inner.map.get_mut(key) else {
            drop(inner);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let old_seq = entry.seq;
        entry.seq = seq;
        let hit = CachedFile {
            data: entry.data.clone(),
            etag: entry.etag.clone(),
        };
        inner.next_seq += 1;
        inner.order.remove(&old_seq);
        inner.order.insert(seq, key.to_string());
        drop(inner);

        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(hit)
    }

    /// Store `data` and return it with its ETag.  Oversized entries are handed
    /// straight back without being cached, so callers always get an ETag.
    pub fn insert(&self, key: &str, data: Arc<Vec<u8>>) -> CachedFile {
        let etag: Arc<str> = Arc::from(compute_etag(&data));
        let size = data.len();

        let file = CachedFile {
            data: data.clone(),
            etag: etag.clone(),
        };

        // One file must not be allowed to own the whole budget.
        if self.max_size == 0 || size as f64 > self.max_memory_bytes as f64 * 0.1 {
            return file;
        }

        let mut inner = self.inner.lock().unwrap();

        if let Some(old) = inner.map.remove(key) {
            inner.current_memory -= old.size;
            inner.order.remove(&old.seq);
        }

        while (inner.map.len() >= self.max_size
            || inner.current_memory + size > self.max_memory_bytes)
            && !inner.map.is_empty()
        {
            let Some((&oldest_seq, oldest_key)) = inner.order.iter().next() else {
                break;
            };
            let oldest_key = oldest_key.clone();
            inner.order.remove(&oldest_seq);
            if let Some(removed) = inner.map.remove(&oldest_key) {
                inner.current_memory -= removed.size;
            }
        }

        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.order.insert(seq, key.to_string());
        inner.map.insert(
            key.to_string(),
            Entry {
                data,
                etag,
                size,
                seq,
            },
        );
        inner.current_memory += size;

        file
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().unwrap();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        CacheStats {
            size: inner.map.len(),
            max_size: self.max_size,
            memory_used_mb: format!("{:.2}", inner.current_memory as f64 / 1024.0 / 1024.0),
            max_memory_mb: format!("{:.0}", self.max_memory_bytes as f64 / 1024.0 / 1024.0),
            hits,
            misses,
            hit_rate: format!("{hit_rate:.2}%"),
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }

    #[cfg(test)]
    pub fn memory_used(&self) -> usize {
        self.inner.lock().unwrap().current_memory
    }
}

/// Shaped exactly like the reference's `/api/cache-stats` payload, including
/// the string-typed megabyte figures — clients parse this.
#[derive(serde::Serialize)]
pub struct CacheStats {
    pub size: usize,
    #[serde(rename = "maxSize")]
    pub max_size: usize,
    #[serde(rename = "memoryUsedMB")]
    pub memory_used_mb: String,
    #[serde(rename = "maxMemoryMB")]
    pub max_memory_mb: String,
    pub hits: u64,
    pub misses: u64,
    #[serde(rename = "hitRate")]
    pub hit_rate: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(n: usize, fill: u8) -> Arc<Vec<u8>> {
        Arc::new(vec![fill; n])
    }

    #[test]
    fn etag_matches_the_reference_recipe() {
        // md5("hello") = 5d41402abc4b2a76b9719d911017c592
        assert_eq!(compute_etag(b"hello"), "5d41402abc4b2a76");
    }

    #[test]
    fn round_trips_and_counts_hits() {
        let cache = FileCache::new(10, 1);
        cache.insert("a", blob(16, 1));
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        let s = cache.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
        assert_eq!(s.hit_rate, "50.00%");
    }

    #[test]
    fn evicts_least_recently_used_first() {
        let cache = FileCache::new(2, 1);
        cache.insert("a", blob(16, 1));
        cache.insert("b", blob(16, 2));
        cache.get("a"); // 'a' is now the most recent, so 'b' is next out
        cache.insert("c", blob(16, 3));
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn refuses_entries_larger_than_a_tenth_of_the_budget() {
        let cache = FileCache::new(100, 1); // 1 MB budget, 100 KB ceiling
        let file = cache.insert("big", blob(200 * 1024, 7));
        assert_eq!(cache.len(), 0);
        // Still returned to the caller, with a usable ETag.
        assert_eq!(file.data.len(), 200 * 1024);
        assert_eq!(file.etag.len(), 16);
    }

    #[test]
    fn evicts_until_both_limits_are_satisfied() {
        let cache = FileCache::new(100, 1);
        // 16 x 80 KB is 1.25 MB against a 1 MB budget, so some must go.
        for i in 0..16 {
            cache.insert(&format!("f{i}"), blob(80 * 1024, i as u8));
        }
        assert!(cache.memory_used() <= 1024 * 1024);
        assert!(cache.len() < 16);
        // The most recent insert always survives.
        assert!(cache.get("f15").is_some());
    }

    #[test]
    fn replacing_a_key_does_not_double_count_memory() {
        let cache = FileCache::new(10, 1);
        cache.insert("a", blob(1000, 1));
        cache.insert("a", blob(2000, 2));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.memory_used(), 2000);
    }
}
