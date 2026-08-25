//! Startup validation.
//!
//! The reference spends a thousand lines here and it earns them: most support
//! questions about this server are answered by reading its output.  The same
//! findings are served at `/api/health`, so a bundled app can show them without
//! anyone having to find a terminal.

use std::path::Path;

use serde_json::{json, Value};

use crate::config::{parse_data_ini, parse_target, Config};
use crate::grf::{Grf, GrfError};
use crate::util::iso_now;

pub struct Validation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
    pub details: Value,
}

impl Validation {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }

    /// The payload `/api/health` merges its live statistics into.
    pub fn status_json(&self) -> Value {
        json!({
            "timestamp": iso_now(),
            "status": if self.success() { "ok" } else { "error" },
            "hasWarnings": !self.warnings.is_empty(),
            "summary": {
                "errors": self.errors.len(),
                "warnings": self.warnings.len(),
                "info": self.info.len(),
            },
            "details": self.details,
            "messages": {
                "errors": self.errors,
                "warnings": self.warnings,
                "info": self.info,
            },
        })
    }

    pub fn print_report(&self) {
        println!("\n{}", "=".repeat(80));
        println!("VALIDATION REPORT");
        println!("{}\n", "=".repeat(80));

        if !self.info.is_empty() {
            println!("INFO:");
            for message in &self.info {
                print_multiline("  ", message);
            }
            println!();
        }
        if !self.warnings.is_empty() {
            println!("WARNINGS:");
            for message in &self.warnings {
                print_multiline("  ", message);
            }
            println!();
        }
        if !self.errors.is_empty() {
            println!("ERRORS:");
            for message in &self.errors {
                print_multiline("  ", message);
            }
            println!();
        }

        println!("{}", "=".repeat(80));
        if self.success() {
            println!("Validation completed successfully.");
            if !self.warnings.is_empty() {
                println!("{} warning(s) found", self.warnings.len());
            }
        } else {
            println!("Validation failed.");
            println!("   {} error(s) found", self.errors.len());
        }
        println!("{}\n", "=".repeat(80));
    }
}

fn print_multiline(prefix: &str, text: &str) {
    for line in text.lines() {
        println!("{prefix}{line}");
    }
}

const REPACK_HINT: &str = concat!(
    "  FIX: repack the archive with GRF Editor:\n",
    "  1. Download GRF Editor: https://github.com/Tokeiburu/GRFEditor\n",
    "  2. File -> Options -> Repack type -> Decrypt\n",
    "  3. Tools -> Repack\n",
    "  4. Replace the original file when it finishes"
);

struct Builder {
    errors: Vec<String>,
    warnings: Vec<String>,
    info: Vec<String>,
}

impl Builder {
    fn error(&mut self, m: impl Into<String>) {
        self.errors.push(m.into());
    }
    fn warn(&mut self, m: impl Into<String>) {
        self.warnings.push(m.into());
    }
    fn note(&mut self, m: impl Into<String>) {
        self.info.push(m.into());
    }
}

/// Run every check and load the archives in one pass — parsing a 100,000-entry
/// file table twice to say the same thing about it costs seconds at startup.
pub fn validate_and_load(cfg: &Config) -> (Vec<Grf>, Validation) {
    let mut b = Builder {
        errors: Vec::new(),
        warnings: Vec::new(),
        info: Vec::new(),
    };

    let env_details = validate_environment(cfg, &mut b);
    let files_details = validate_required_files(cfg, &mut b);
    let (grfs, grf_details) = validate_grfs(cfg, &mut b);

    let details = json!({
        "runtime": {
            "implementation": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "valid": true,
        },
        "dependencies": { "installed": true, "static": true },
        "env": env_details,
        "files": files_details,
        "grfs": grf_details,
    });

    (
        grfs,
        Validation {
            errors: b.errors,
            warnings: b.warnings,
            info: b.info,
            details,
        },
    )
}

fn looks_like_url(value: &str) -> bool {
    match value.split_once("://") {
        Some((scheme, rest)) => !scheme.is_empty() && !rest.is_empty(),
        None => false,
    }
}

fn validate_environment(cfg: &Config, b: &mut Builder) -> Value {
    let mut variables = serde_json::Map::new();

    b.note(format!("PORT: {}", cfg.port));
    variables.insert("PORT".into(), json!({ "value": cfg.port }));

    match &cfg.client_public_url {
        None => {
            b.error("CLIENT_PUBLIC_URL not set! Configure it in the .env file");
            variables.insert(
                "CLIENT_PUBLIC_URL".into(),
                json!({ "defined": false, "error": "Variable not set" }),
            );
        }
        Some(url) if !looks_like_url(url) => {
            b.error(format!("Invalid CLIENT_PUBLIC_URL: {url}"));
            variables.insert(
                "CLIENT_PUBLIC_URL".into(),
                json!({ "defined": true, "invalid": true, "value": url }),
            );
        }
        Some(url) => {
            b.note(format!("CLIENT_PUBLIC_URL: {url}"));
            variables.insert(
                "CLIENT_PUBLIC_URL".into(),
                json!({ "defined": true, "value": url }),
            );
        }
    }

    b.note(format!("NODE_ENV: {}", cfg.node_env));
    variables.insert("NODE_ENV".into(), json!({ "value": cfg.node_env }));

    if cfg.enable_static_serve {
        if cfg.robrowser_path.is_dir() {
            b.note(format!(
                "ENABLE_STATIC_SERVE: serving {}",
                cfg.robrowser_path.display()
            ));
        } else {
            b.warn(format!(
                "ENABLE_STATIC_SERVE is on but ROBROWSER_PATH does not exist: {}",
                cfg.robrowser_path.display()
            ));
        }
        variables.insert(
            "ROBROWSER_PATH".into(),
            json!({
                "value": cfg.robrowser_path.to_string_lossy(),
                "exists": cfg.robrowser_path.is_dir(),
            }),
        );
    }

    if cfg.enable_wsproxy {
        let invalid: Vec<&String> = cfg
            .ws_allowed_targets
            .iter()
            .filter(|t| parse_target(t).is_none())
            .collect();
        if invalid.is_empty() {
            b.note(format!(
                "WS_ALLOWED_TARGETS: {}",
                cfg.ws_allowed_targets.join(", ")
            ));
        } else {
            b.error(format!(
                "WS_ALLOWED_TARGETS contains invalid entries: {}\n  Each entry must be \"host:port\" where port is 1-65535.",
                invalid
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        variables.insert(
            "WS_ALLOWED_TARGETS".into(),
            json!({ "entries": cfg.ws_allowed_targets }),
        );
    }

    if let Some(path) = &cfg.data_override_path {
        if path.is_dir() {
            b.note(format!("DATA_OVERRIDE_PATH: {}", path.display()));
        } else {
            b.warn(format!(
                "DATA_OVERRIDE_PATH does not exist: {}",
                path.display()
            ));
        }
        variables.insert(
            "DATA_OVERRIDE_PATH".into(),
            json!({ "value": path.to_string_lossy(), "exists": path.is_dir() }),
        );
    }

    if !cfg.root.join(".env").exists() {
        b.warn(".env file not found! Copy .env.example to .env and configure it");
    }

    json!({ "valid": true, "variables": Value::Object(variables) })
}

fn dir_is_empty(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(entries) => !entries
            .flatten()
            .any(|e| !e.file_name().to_string_lossy().starts_with("add-")),
        Err(_) => true,
    }
}

fn validate_required_files(cfg: &Config, b: &mut Builder) -> Value {
    let mut checks = Vec::new();
    let mut valid = true;

    let resources = cfg.resources_dir();
    let resources_exists = resources.is_dir();
    if !resources_exists {
        b.error(format!("{} folder not found!", cfg.client_respath));
        valid = false;
    } else {
        b.note(format!("{} folder OK", cfg.client_respath));
    }
    checks.push(json!({
        "path": cfg.client_respath,
        "type": "dir",
        "required": true,
        "exists": resources_exists,
    }));

    let data_ini = cfg.data_ini_path();
    let data_ini_exists = data_ini.is_file();
    if !data_ini_exists {
        b.error(format!("{} file not found!", data_ini.display()));
        valid = false;
    } else {
        b.note(format!("{} file OK", cfg.client_dataini));
    }
    checks.push(json!({
        "path": data_ini.to_string_lossy(),
        "type": "file",
        "required": true,
        "exists": data_ini_exists,
    }));

    // Loose asset directories that ship beside the archives.  Their absence is
    // not fatal — plenty of clients keep everything inside the GRF — but it is
    // the explanation for a whole class of missing-file reports.
    for name in ["BGM", "data", "System"] {
        let path = cfg.root.join(name);
        let exists = path.is_dir();
        let empty = !exists || dir_is_empty(&path);
        if !exists {
            b.warn(format!(
                "{name}/ folder not found - may cause issues depending on the client"
            ));
        } else if empty {
            b.warn(format!(
                "{name}/ folder is empty - may cause issues depending on the client"
            ));
        } else {
            b.note(format!("{name}/ folder OK"));
        }
        checks.push(json!({
            "path": name,
            "type": "dir",
            "required": false,
            "exists": exists,
            "isEmpty": empty,
        }));
    }

    json!({ "valid": valid, "checks": checks })
}

fn validate_grfs(cfg: &Config, b: &mut Builder) -> (Vec<Grf>, Value) {
    let data_ini = cfg.data_ini_path();
    let Ok(content) = std::fs::read_to_string(&data_ini) else {
        // Already reported by validate_required_files; nothing usable to add.
        return (
            Vec::new(),
            json!({ "valid": false, "reason": "DATA.INI missing or unreadable" }),
        );
    };

    let listed = parse_data_ini(&content);
    if listed.is_empty() {
        b.error(format!(
            "No GRF files found in {}! Add them to the [Data] section.",
            data_ini.display()
        ));
        return (
            Vec::new(),
            json!({ "valid": false, "reason": "No GRF files in DATA.INI" }),
        );
    }

    let resources = cfg.resources_dir();
    let mut grfs = Vec::new();
    let mut results = Vec::new();
    let mut all_valid = true;

    for (order, name) in listed.iter().enumerate() {
        let path = resources.join(name);
        if !path.is_file() {
            b.error(format!("GRF not found: {name}"));
            results.push(json!({ "file": name, "order": order, "exists": false }));
            all_valid = false;
            continue;
        }

        match Grf::open_with_encoding(&path, cfg.grf_filename_encoding) {
            Ok(grf) => {
                let stats = &grf.stats;
                b.note(format!(
                    "Valid GRF: {name} (version 0x{:X}, {} files)",
                    grf.version, stats.file_count
                ));

                // Non-UTF-8 names are normal for kRO and must not read as a
                // fault, but they have to be visible: they are the difference
                // between "works" and "every Korean sprite is missing".
                if stats.non_utf8_name_count > 0 {
                    let samples = stats.non_utf8_samples.join(" | ");
                    b.warn(format!(
                        "GRF path encoding: {name} has {} non-UTF-8 filenames, decoded as {}. This is normal for Korean clients. Examples: {samples}",
                        stats.non_utf8_name_count,
                        stats.detected_encoding.as_str()
                    ));
                }
                if stats.encrypted_count > 0 {
                    b.note(format!(
                        "{name}: {} DES-encrypted entries will be decrypted on read",
                        stats.encrypted_count
                    ));
                }

                results.push(json!({
                    "file": name,
                    "path": grf.path.to_string_lossy(),
                    "order": order,
                    "exists": true,
                    "valid": true,
                    "version": format!("0x{:X}", grf.version),
                    "compatible": true,
                    "fileTable": {
                        "ok": true,
                        "compressedSize": stats.table_compressed_size,
                        "uncompressedSize": stats.table_real_size,
                    },
                    "pathEncoding": {
                        "ok": true,
                        "encoding": stats.detected_encoding.as_str(),
                        "totalFilesInspected": stats.file_count,
                        "invalidUtf8Count": stats.non_utf8_name_count,
                        "invalidUtf8Samples": stats.non_utf8_samples,
                        "badNameCount": stats.bad_name_count,
                    },
                    "encryptedEntries": stats.encrypted_count,
                    "fileCount": stats.file_count,
                }));
                grfs.push(grf);
            }
            Err(e) => {
                all_valid = false;
                let version = match &e {
                    GrfError::UnsupportedVersion(v) => format!("0x{v:X}"),
                    _ => "unknown".to_string(),
                };
                b.error(format!("Incompatible GRF: {name}\n  {e}\n\n{REPACK_HINT}"));
                results.push(json!({
                    "file": name,
                    "order": order,
                    "exists": true,
                    "valid": false,
                    "version": version,
                    "compatible": false,
                    "reason": e.to_string(),
                }));
            }
        }
    }

    (
        grfs,
        json!({
            "valid": all_valid,
            "count": listed.len(),
            "loadOrder": listed,
            "files": results,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_shape_check() {
        assert!(looks_like_url("http://127.0.0.1:8000"));
        assert!(looks_like_url("https://play.example.com"));
        assert!(!looks_like_url("127.0.0.1:8000"));
        assert!(!looks_like_url("http://"));
    }
}
