//! Tripwire placement: create decoy files safely, remember exactly what was created, remove only what is still ours.
//! Mirrors `WardAgent._place_tripwires` in the Python reference. Rules, all enforced here and tested:
//!  - the folder must be an absolute LOCAL path that exists; never a drive root, a network path, or an operating-system folder;
//!  - the path must not pass through a link/junction (a link to a tripwire would make the real target the tripwire);
//!  - NEVER replace an existing file: creation is atomic `create_new`, so there is no check-then-write race;
//!  - the decoy is bland (no word like "honeypot" or "halvard" in it) and sorts first in the folder, where file-encrypting programs usually start;
//!  - removal deletes a file only if its content still matches what was placed.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEFAULT_NAMES: &[&str] = &["!000-budget-draft.xlsx", "!000-meeting-notes.docx"];
const EXTENSIONS: &[&str] = &["xlsx", "docx", "pptx", "pdf", "txt", "csv"];
/// Folders (first path component under the drive, lower case) that are never used.
const FORBIDDEN: &[&str] = &["windows", "program files", "program files (x86)", "programdata", "system volume information", "$recycle.bin", "recovery", "boot", "perflogs"];

#[derive(Debug, PartialEq, Eq)]
pub enum Placed {
    Created(PathBuf),
    Skipped { path: PathBuf, why: String },
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic decoy bytes for an id and extension (same as the Python reference).
pub fn decoy_bytes(id: &str, ext: &str) -> Vec<u8> {
    let seed = Sha256::digest(id.as_bytes());
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let body: Vec<u8> = format!("Reference {seed_hex}\n").repeat(40).into_bytes();
    match ext {
        "pdf" => [b"%PDF-1.4\n".to_vec(), body].concat(),
        "docx" | "xlsx" | "pptx" => [b"PK\x03\x04".to_vec(), seed.to_vec().repeat(30), body].concat(),
        _ => body,
    }
}

/// Pure check of a folder path string (no file-system access): is it an acceptable place for a tripwire?
pub fn check_dir_text(dir: &str) -> Result<(), String> {
    let d = dir.replace('/', "\\");
    if d.starts_with("\\\\") {
        return Err("network and device paths (\\\\...) are never used".into());
    }
    let b = d.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return Err("the folder must be an absolute local path such as C:\\Users\\name\\Documents".into());
    }
    let rest = d[3..].trim_end_matches('\\');
    if rest.is_empty() {
        return Err("a drive root is never used".into());
    }
    let first = rest.split('\\').next().unwrap_or("").to_lowercase();
    if FORBIDDEN.contains(&first.as_str()) {
        return Err(format!("operating-system folder '{first}' is never used"));
    }
    if rest.split('\\').any(|p| p == ".." || p == ".") {
        return Err("the path must not contain '.' or '..' parts".into());
    }
    Ok(())
}

pub fn check_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains(['\\', '/', ':', '\0']) || name == "." || name == ".." || name.ends_with('.') || name.ends_with(' ') {
        return Err(format!("unsafe file name {name:?}"));
    }
    let ext = Path::new(name).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    if !EXTENSIONS.contains(&ext.as_str()) {
        return Err(format!("file type .{ext} not allowed (use one of {})", EXTENSIONS.join(", ")));
    }
    Ok(ext)
}

fn norm(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    s.trim_start_matches("\\\\?\\").trim_end_matches('\\').to_lowercase()
}

/// The folder must exist and must not be (or sit inside) a link: its canonical form has to equal the form given.
fn check_dir_fs(dir: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        return Err("the folder does not exist".into());
    }
    let canon = dir.canonicalize().map_err(|e| format!("cannot resolve the folder: {e}"))?;
    if norm(&canon) != norm(dir) {
        return Err(format!("the path goes through a link or junction (it resolves to {}); use the real folder", canon.display()));
    }
    Ok(())
}

fn load_manifest(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["tripwires"].as_array().cloned()).unwrap_or_default()
}

fn save_manifest(path: &Path, entries: &[Value]) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("cannot create {}: {e}", p.display()))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&json!({"version": 1, "tripwires": entries})).unwrap()).map_err(|e| e.to_string())
}

pub fn default_manifest() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into())).join("Halvard").join("tripwires.json")
}

/// Place decoys named `names` in `dir`. The manifest records the sha256 of every file created.
pub fn place(dir: &str, names: &[String], manifest: &Path) -> Result<Vec<Placed>, String> {
    check_dir_text(dir)?;
    let d = Path::new(dir);
    check_dir_fs(d)?;
    let mut entries = load_manifest(manifest);
    let mut out = Vec::new();
    for name in names {
        let ext = check_name(name)?;
        let path = d.join(name);
        let data = decoy_bytes(&format!("{}|{}", norm(d), name.to_lowercase()), &ext);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(&data).map_err(|e| format!("write failed: {e}"))?;
                entries.push(json!({"path": path.to_string_lossy(), "sha256": sha256_hex(&data), "id": name}));
                out.push(Placed::Created(path));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                out.push(Placed::Skipped { path, why: "a file already exists there; Halvard never replaces an existing file".into() })
            }
            Err(e) => out.push(Placed::Skipped { path, why: format!("cannot create: {e}") }),
        }
    }
    save_manifest(manifest, &entries)?;
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Ok,
    Changed,
    Missing,
}

pub fn status(manifest: &Path) -> Vec<(String, State)> {
    load_manifest(manifest)
        .iter()
        .map(|e| {
            let p = e["path"].as_str().unwrap_or("").to_string();
            let st = match std::fs::read(&p) {
                Err(_) => State::Missing,
                Ok(b) if sha256_hex(&b) == e["sha256"].as_str().unwrap_or("") => State::Ok,
                Ok(_) => State::Changed,
            };
            (p, st)
        })
        .collect()
}

/// Remove every tripwire that is still exactly what was placed. Returns (removed, left_in_place).
pub fn remove(manifest: &Path) -> Result<(Vec<String>, Vec<String>), String> {
    let (mut removed, mut left, mut keep) = (Vec::new(), Vec::new(), Vec::new());
    for e in load_manifest(manifest) {
        let p = e["path"].as_str().unwrap_or("").to_string();
        match std::fs::read(&p) {
            Err(_) => removed.push(format!("{p} (already gone)")),
            Ok(b) if sha256_hex(&b) == e["sha256"].as_str().unwrap_or("") => match std::fs::remove_file(&p) {
                Ok(_) => removed.push(p),
                Err(err) => {
                    left.push(format!("{p} (cannot delete: {err})"));
                    keep.push(e);
                }
            },
            Ok(_) => {
                left.push(format!("{p} (changed since it was placed, so it is not ours to delete)"));
                keep.push(e);
            }
        }
    }
    save_manifest(manifest, &keep)?;
    Ok((removed, left))
}
