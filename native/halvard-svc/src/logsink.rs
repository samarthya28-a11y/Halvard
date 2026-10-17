//! One place every alert line goes: stdout (when there is a console) and, when set, an append-only file with simple size-capped rotation.
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_BYTES: u64 = 5 * 1024 * 1024;
static FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn set_file(path: PathBuf) {
    *FILE.lock().unwrap() = Some(path);
}

pub fn emit(line: &str) {
    println!("{line}");
    let Ok(g) = FILE.lock() else { return };
    let Some(p) = g.as_ref() else { return };
    if std::fs::metadata(p).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
        let _ = std::fs::rename(p, p.with_extension("log.1")); // keep one previous file, so the log can never fill the disk
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "{line}");
    }
}
