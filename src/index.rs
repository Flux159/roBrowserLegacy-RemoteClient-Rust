//! The merged, normalised file index.
//!
//! One entry in a GRF answers to several spellings.  roBrowser asks for CP949
//! bytes reinterpreted as Latin-1 with forward slashes; the archive stores
//! Korean Unicode with backslashes; and case is irrelevant to both.  Every
//! entry is therefore inserted under four keys, first spelling wins:
//!
//! 1. stored name, `\` -> `/`
//! 2. stored name, `/` -> `\`
//! 3. mojibake name, `\` -> `/`
//! 4. mojibake name, `/` -> `\`
//!
//! Miss any of these and the client loads, walks around, and silently has no
//! sprite for anything with Hangul in its path — which is most of them.

use std::collections::HashMap;

use crate::encoding::{js_lowercase, to_mojibake};
use crate::grf::{Grf, GrfEntry};

pub struct IndexedFile {
    /// The archive this came from, as an index into the load order.
    pub grf: u16,
    /// The name exactly as the archive spells it.
    pub name: String,
    pub entry: GrfEntry,
}

pub struct AssetIndex {
    files: Vec<IndexedFile>,
    keys: HashMap<Box<str>, u32>,
    /// Number of files that won at least one key, i.e. are reachable.
    reachable: Vec<u32>,
    pub mojibake_key_count: usize,
}

/// Lowercase, all forward slashes.
pub fn norm_forward(path: &str) -> String {
    js_lowercase(path).replace('\\', "/")
}

/// Lowercase, all backslashes.
pub fn norm_backward(path: &str) -> String {
    js_lowercase(path).replace('/', "\\")
}

impl AssetIndex {
    /// Build the merged index. `grfs` must be in DATA.INI order — index 0 is
    /// the highest-priority overlay and its files win every collision.
    pub fn build(grfs: &[Grf]) -> AssetIndex {
        let total: usize = grfs.iter().map(|g| g.files.len()).sum();
        let mut files: Vec<IndexedFile> = Vec::with_capacity(total);
        let mut keys: HashMap<Box<str>, u32> = HashMap::with_capacity(total * 2);
        let mut reachable: Vec<u32> = Vec::with_capacity(total);
        let mut mojibake_key_count = 0usize;

        for (grf_idx, grf) in grfs.iter().enumerate() {
            for file in &grf.files {
                let slot = files.len() as u32;
                let mut won_any = false;

                let claim = |key: String, keys: &mut HashMap<Box<str>, u32>| -> bool {
                    if keys.contains_key(key.as_str()) {
                        false
                    } else {
                        keys.insert(key.into_boxed_str(), slot);
                        true
                    }
                };

                won_any |= claim(norm_forward(&file.name), &mut keys);
                won_any |= claim(norm_backward(&file.name), &mut keys);

                let mojibake = to_mojibake(&file.name);
                if mojibake != file.name {
                    if claim(norm_forward(&mojibake), &mut keys) {
                        won_any = true;
                        mojibake_key_count += 1;
                    }
                    won_any |= claim(norm_backward(&mojibake), &mut keys);
                }

                if won_any {
                    reachable.push(slot);
                }
                files.push(IndexedFile {
                    grf: grf_idx as u16,
                    name: file.name.clone(),
                    entry: file.entry,
                });
            }
        }

        keys.shrink_to_fit();
        reachable.shrink_to_fit();

        AssetIndex {
            files,
            keys,
            reachable,
            mojibake_key_count,
        }
    }

    pub fn empty() -> AssetIndex {
        AssetIndex {
            files: Vec::new(),
            keys: HashMap::new(),
            reachable: Vec::new(),
            mojibake_key_count: 0,
        }
    }

    /// Look a request path up under both slash spellings.
    pub fn lookup(&self, path: &str) -> Option<&IndexedFile> {
        let forward = norm_forward(path);
        if let Some(&i) = self.keys.get(forward.as_str()) {
            return Some(&self.files[i as usize]);
        }
        let backward = norm_backward(path);
        if let Some(&i) = self.keys.get(backward.as_str()) {
            return Some(&self.files[i as usize]);
        }
        None
    }

    /// Total number of index keys — the figure the reference reports as
    /// `index.totalFiles`, which counts spellings rather than files.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn reachable_count(&self) -> usize {
        self.reachable.len()
    }

    /// Every reachable file, spelled as its archive spells it.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.reachable
            .iter()
            .map(move |&i| self.files[i as usize].name.as_str())
    }

    pub fn reachable_files(&self) -> impl Iterator<Item = &IndexedFile> {
        self.reachable.iter().map(move |&i| &self.files[i as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::FilenameEncoding;
    use crate::grf::{GrfEntry, GrfFile, GrfStats};

    fn fake_grf(names: &[&str]) -> Grf {
        // Only the fields the index touches are meaningful here.
        Grf {
            path: std::path::PathBuf::from("fake.grf"),
            file_name: "fake.grf".into(),
            version: 0x200,
            files: names
                .iter()
                .map(|n| GrfFile {
                    name: (*n).to_string(),
                    entry: GrfEntry {
                        offset: 0,
                        compressed_size: 1,
                        length_aligned: 1,
                        real_size: 1,
                        kind: 1,
                    },
                })
                .collect(),
            stats: GrfStats {
                file_count: names.len(),
                bad_name_count: 0,
                non_utf8_name_count: 0,
                non_utf8_samples: vec![],
                encrypted_count: 0,
                detected_encoding: FilenameEncoding::Cp949,
                table_compressed_size: 0,
                table_real_size: 0,
            },
            handle: std::fs::File::open("/dev/null").unwrap(),
        }
    }

    #[test]
    fn all_four_spellings_resolve_to_the_same_entry() {
        let grf = fake_grf(&["data\\sprite\\인간족\\검사\\검사_남.act"]);
        let index = AssetIndex::build(std::slice::from_ref(&grf));

        let korean_fwd = "data/sprite/인간족/검사/검사_남.act";
        let korean_back = "data\\sprite\\인간족\\검사\\검사_남.act";
        let moji_fwd = to_mojibake(korean_fwd);
        let moji_back = to_mojibake(korean_back);

        for spelling in [korean_fwd, korean_back, &moji_fwd, &moji_back] {
            let hit = index.lookup(spelling);
            assert!(hit.is_some(), "no hit for {spelling}");
            assert_eq!(hit.unwrap().name, "data\\sprite\\인간족\\검사\\검사_남.act");
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let grf = fake_grf(&["DATA\\Texture\\Foo.BMP"]);
        let index = AssetIndex::build(std::slice::from_ref(&grf));
        assert!(index.lookup("data/texture/foo.bmp").is_some());
        assert!(index.lookup("DATA/TEXTURE/FOO.BMP").is_some());
    }

    #[test]
    fn lower_indexed_archives_win() {
        let overlay = fake_grf(&["data\\override.txt"]);
        let base = fake_grf(&["data\\override.txt"]);
        let index = AssetIndex::build(&[overlay, base]);
        assert_eq!(index.lookup("data/override.txt").unwrap().grf, 0);
    }

    #[test]
    fn only_reachable_files_are_listed() {
        let overlay = fake_grf(&["data\\dup.txt"]);
        let base = fake_grf(&["data\\dup.txt", "data\\only-in-base.txt"]);
        let index = AssetIndex::build(&[overlay, base]);
        let names: Vec<&str> = index.names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"data\\dup.txt"));
        assert!(names.contains(&"data\\only-in-base.txt"));
    }

    #[test]
    fn ascii_names_do_not_get_mojibake_keys() {
        let grf = fake_grf(&["data\\plain.txt"]);
        let index = AssetIndex::build(std::slice::from_ref(&grf));
        assert_eq!(index.mojibake_key_count, 0);
        assert_eq!(index.key_count(), 2);
    }
}
