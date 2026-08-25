//! Configuration.  Same variable names, same defaults and same `.env` handling
//! as the reference implementation, because a drop-in replacement that needs
//! its own configuration is not a drop-in replacement.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::encoding::FilenameEncoding;

pub const DEFAULT_WS_TARGETS: [&str; 3] = ["127.0.0.1:6900", "127.0.0.1:6121", "127.0.0.1:5121"];

pub struct Config {
    /// Everything relative — `resources/`, `data/`, `logs/`, `index.html` — is
    /// resolved against this.  The working directory, unless `SERVER_ROOT` says
    /// otherwise (which is how the embedded build points at its app bundle).
    pub root: PathBuf,
    pub port: u16,
    pub bind: String,
    pub client_public_url: Option<String>,
    pub is_prod: bool,
    pub node_env: String,
    pub enable_static_serve: bool,
    pub enable_wsproxy: bool,
    pub enable_compression: bool,
    pub robrowser_path: PathBuf,
    pub ws_allowed_targets: Vec<String>,
    pub data_override_path: Option<PathBuf>,
    pub cache_max_files: usize,
    pub cache_max_memory_mb: usize,
    pub cache_warm_up: bool,
    pub cache_warm_up_limit: usize,
    pub client_respath: String,
    pub client_dataini: String,
    pub client_enablesearch: bool,
    /// Write every served asset out to `<root>/<path>` as it is extracted, so
    /// the next request for it is answered from disk rather than from the
    /// archive.  On by default, matching the reference.
    ///
    /// The cost is a second copy of everything the client has ever touched, and
    /// a server that keeps serving those copies after an archive is replaced —
    /// clear the extracted tree when you swap a GRF.
    pub client_autoextract: bool,
    /// Override GRF filename decoding instead of detecting it.  `auto` (the
    /// default) is right almost always; this is the escape hatch for an archive
    /// it gets wrong.
    pub grf_filename_encoding: Option<FilenameEncoding>,
}

/// Resolve a path and make it absolute, without the `\\?\` prefix that
/// `canonicalize` adds on Windows.
///
/// Verbatim paths are passed to the object manager unnormalised, so they do not
/// accept `/` as a separator and do not resolve `..`.  Since every path here is
/// then joined with configuration written by a human — `resources/`,
/// `../roBrowserLegacy/dist/Web` — keeping the prefix turns ordinary settings
/// into paths that cannot be opened.
fn resolve(path: PathBuf) -> PathBuf {
    let resolved = std::fs::canonicalize(&path).unwrap_or(path);

    #[cfg(windows)]
    {
        let text = resolved.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            // Leave `\\?\UNC\server\share` alone: stripping it would produce a
            // path that no longer names the same thing.
            let is_drive = rest.as_bytes().get(1) == Some(&b':');
            if is_drive && !rest.starts_with("UNC\\") {
                return PathBuf::from(rest.to_string());
            }
        }
    }

    resolved
}

/// Join a configured relative path onto a root one component at a time.
///
/// `CLIENT_RESPATH` conventionally ends in a separator and may use either kind,
/// and pushing it whole would leave that separator embedded in the result.
fn join_relative(root: &Path, relative: &str) -> PathBuf {
    let candidate = Path::new(relative);
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }
    let mut path = root.to_path_buf();
    for part in relative.split(['/', '\\']).filter(|p| !p.is_empty()) {
        path.push(part);
    }
    path
}

fn env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env(key) {
        Some(v) => v == "true",
        None => default,
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    env(key)
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

/// Minimal `.env` reader: `KEY=value`, `#`/`;` comments, optional `export`
/// prefix, optional single or double quotes.  Existing environment variables
/// always win, matching dotenv.
pub fn load_dotenv(path: &Path) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return found;
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut value = value.trim();
        if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value = &value[1..value.len() - 1];
        } else if let Some(hash) = value.find(" #") {
            // Unquoted trailing comment.
            value = value[..hash].trim_end();
        }

        found.insert(key.to_string(), value.to_string());
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }

    found
}

impl Config {
    pub fn from_env() -> Config {
        let root = resolve(
            env("SERVER_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
        );

        let node_env = env("NODE_ENV").unwrap_or_else(|| "development".to_string());
        let is_prod = node_env == "production";

        let robrowser_path = resolve(join_relative(
            &root,
            &env("ROBROWSER_PATH").unwrap_or_else(|| "../roBrowserLegacy".to_string()),
        ));

        let data_override_path =
            env("DATA_OVERRIDE_PATH").map(|raw| resolve(join_relative(&root, &raw)));

        let ws_allowed_targets = match env("WS_ALLOWED_TARGETS") {
            Some(raw) => raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => DEFAULT_WS_TARGETS.iter().map(|s| s.to_string()).collect(),
        };

        Config {
            root,
            port: env("PORT")
                .and_then(|v| v.trim().parse::<u16>().ok())
                .unwrap_or(3338),
            bind: env("HOST").unwrap_or_else(|| "0.0.0.0".to_string()),
            client_public_url: env("CLIENT_PUBLIC_URL"),
            is_prod,
            node_env,
            enable_static_serve: env_bool("ENABLE_STATIC_SERVE", false),
            enable_wsproxy: env_bool("ENABLE_WSPROXY", false),
            enable_compression: env_bool("ENABLE_COMPRESSION", true),
            robrowser_path,
            ws_allowed_targets,
            data_override_path,
            cache_max_files: env_usize("CACHE_MAX_FILES", 5000),
            cache_max_memory_mb: env_usize("CACHE_MAX_MEMORY_MB", 1024),
            cache_warm_up: env_bool("CACHE_WARM_UP", false),
            cache_warm_up_limit: env_usize("CACHE_WARM_UP_LIMIT", 500),
            client_respath: env("CLIENT_RESPATH").unwrap_or_else(|| "resources/".to_string()),
            client_dataini: env("CLIENT_DATAINI").unwrap_or_else(|| "DATA.INI".to_string()),
            client_enablesearch: env_bool("CLIENT_ENABLESEARCH", true),
            client_autoextract: env_bool("CLIENT_AUTOEXTRACT", true),
            grf_filename_encoding: match env("GRF_FILENAME_ENCODING").as_deref() {
                Some("cp949") | Some("euc-kr") => Some(FilenameEncoding::Cp949),
                Some("utf-8") | Some("utf8") => Some(FilenameEncoding::Utf8),
                _ => None,
            },
        }
    }

    pub fn resources_dir(&self) -> PathBuf {
        join_relative(&self.root, &self.client_respath)
    }

    pub fn data_ini_path(&self) -> PathBuf {
        join_relative(&self.resources_dir(), &self.client_dataini)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn missing_files_log(&self) -> PathBuf {
        self.logs_dir().join("missing-files.log")
    }
}

/// Parse a `host:port` target the way the proxy must: `rfind(':')`, so that a
/// bracketed IPv6 literal keeps its colons.
pub fn parse_target(target: &str) -> Option<(String, u16)> {
    let idx = target.rfind(':')?;
    let host = &target[..idx];
    let port: u32 = target[idx + 1..].parse().ok()?;
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    Some((host.to_string(), port as u16))
}

/// The `[Data]` section of a DATA.INI, in index order.
///
/// Keys are numeric and **lower wins**: overlay archives are listed first on
/// purpose.  Entries are sorted by index rather than by line order, because
/// that is what the client itself does.
pub fn parse_data_ini(content: &str) -> Vec<String> {
    let mut entries: Vec<(i64, String)> = Vec::new();
    let mut in_data = false;
    let mut fallback_index = 1_000_000i64;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_data = line[1..line.len() - 1].trim().eq_ignore_ascii_case("data");
            continue;
        }
        if !in_data {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let index = key.trim().parse::<i64>().unwrap_or_else(|_| {
            fallback_index += 1;
            fallback_index
        });
        entries.push((index, value.to_string()));
    }

    entries.sort_by_key(|(i, _)| *i);
    entries.into_iter().map(|(_, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_ini_keeps_lower_indices_first() {
        let ini = "[Data]\n0=custom.grf\n1=rdata.grf\n2=data.grf\n";
        assert_eq!(
            parse_data_ini(ini),
            vec!["custom.grf", "rdata.grf", "data.grf"]
        );
    }

    #[test]
    fn data_ini_sorts_by_index_not_by_line_order() {
        let ini = "[Data]\n2=data.grf\n0=custom.grf\n1=rdata.grf\n";
        assert_eq!(
            parse_data_ini(ini),
            vec!["custom.grf", "rdata.grf", "data.grf"]
        );
    }

    #[test]
    fn data_ini_ignores_other_sections_and_comments() {
        let ini = "; a comment\n[Flags]\n0=nope.grf\n[data]\n0=yes.grf\n[Other]\n0=no.grf\n";
        assert_eq!(parse_data_ini(ini), vec!["yes.grf"]);
    }

    #[test]
    fn data_ini_handles_crlf_and_spacing() {
        let ini = "[Data]\r\n 0 = custom.grf \r\n1=data.grf\r\n";
        assert_eq!(parse_data_ini(ini), vec!["custom.grf", "data.grf"]);
    }

    #[test]
    fn a_trailing_separator_in_client_respath_does_not_survive_the_join() {
        // The default is "resources/", and on Windows a `\\?\` root would treat
        // an embedded forward slash as an ordinary character rather than a
        // separator — so DATA.INI would simply never be found.
        let root = Path::new("/srv");
        for spelling in ["resources/", "resources", "resources\\", "resources//"] {
            assert_eq!(
                join_relative(root, spelling),
                Path::new("/srv/resources"),
                "{spelling}"
            );
        }
    }

    #[test]
    fn join_relative_handles_nesting_and_absolute_overrides() {
        let root = Path::new("/srv");
        assert_eq!(join_relative(root, "a/b/c"), Path::new("/srv/a/b/c"));
        // An absolute setting replaces the root rather than being appended.
        let absolute = if cfg!(windows) {
            "C:\\elsewhere"
        } else {
            "/elsewhere"
        };
        assert_eq!(join_relative(root, absolute), Path::new(absolute));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_strips_the_verbatim_prefix() {
        let here = resolve(std::env::current_dir().unwrap());
        let text = here.to_string_lossy();
        assert!(!text.starts_with(r"\\?\"), "{text}");
        // And the result still names a real directory.
        assert!(here.is_dir(), "{text}");
    }

    #[test]
    fn target_parsing_survives_ipv6() {
        assert_eq!(
            parse_target("[::1]:6900"),
            Some(("[::1]".to_string(), 6900))
        );
        assert_eq!(
            parse_target("127.0.0.1:6900"),
            Some(("127.0.0.1".to_string(), 6900))
        );
    }

    #[test]
    fn target_parsing_rejects_nonsense() {
        assert_eq!(parse_target("127.0.0.1"), None);
        assert_eq!(parse_target(":6900"), None);
        assert_eq!(parse_target("127.0.0.1:0"), None);
        assert_eq!(parse_target("127.0.0.1:70000"), None);
        assert_eq!(parse_target("127.0.0.1:abc"), None);
    }
}
