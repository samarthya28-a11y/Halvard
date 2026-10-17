//! Port of `src/halvard/ward/detect.py` (F007, behavioral detector for bulk encryption). Pure functions of file content signals; no OS calls.
//! Same thresholds as the Python reference: stop a process when 8 distinct existing files show destroying signals inside 30 s.
use std::collections::{HashMap, HashSet, VecDeque};

const MAGICS: &[&[u8]] = &[
    b"PK\x03\x04", b"%PDF", b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"\xd0\xcf\x11\xe0", b"MZ", b"SQLite format 3", b"{\\rtf", b"RIFF", b"ID3", b"\x1f\x8b", b"7z\xbc\xaf",
    b"Rar!",
];

pub fn entropy(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let n = sample.len() as f64;
    -counts.iter().filter(|&&c| c > 0).map(|&c| (c as f64 / n) * (c as f64 / n).log2()).sum::<f64>()
}

fn looks_text(head: &[u8]) -> bool {
    let s = &head[..head.len().min(256)];
    !s.is_empty() && s.iter().filter(|&&b| (9..=13).contains(&b) || (32..127).contains(&b)).count() as f64 / s.len() as f64 > 0.95
}

pub fn has_magic(head: &[u8]) -> bool {
    MAGICS.iter().any(|m| head.starts_with(m)) || (!head.is_empty() && looks_text(head))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    MagicDestroyed,
    EntropyJump,
    ExtChanged,
}

/// Per-file signals from the old head (up to 512 bytes) and the new sample (up to 4096 bytes). `before` is None when the file did not exist.
pub fn classify(before_head: Option<&[u8]>, after_sample: &[u8], renamed_ext_change: bool) -> Vec<Signal> {
    let mut sig = Vec::new();
    if let Some(before) = before_head {
        let after_head = &after_sample[..after_sample.len().min(256)];
        if !has_magic(after_head) {
            let e_after = entropy(after_sample);
            if e_after > 7.0 && has_magic(before) {
                sig.push(Signal::MagicDestroyed);
            } else if e_after > 7.5 && entropy(before) < 6.5 {
                sig.push(Signal::EntropyJump);
            }
        }
    }
    if renamed_ext_change {
        sig.push(Signal::ExtChanged);
    }
    sig
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub pid: u32,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub files: Vec<String>,
}

struct Seen {
    ts: f64,
    path: String,
    directory: String,
    ext_changed: bool,
}

pub struct Detector {
    window: f64,
    min_files: usize,
    min_dirs: usize,
    events: HashMap<u32, VecDeque<Seen>>,
    fired: HashSet<u32>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector { window: 30.0, min_files: 8, min_dirs: 1, events: HashMap::new(), fired: HashSet::new() }
    }
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one per-file result. Returns a Verdict the first time a process crosses the threshold.
    pub fn observe(&mut self, ts: f64, pid: u32, path: &str, signals: &[Signal]) -> Option<Verdict> {
        if self.fired.contains(&pid) {
            return None;
        }
        if !signals.iter().any(|s| matches!(s, Signal::MagicDestroyed | Signal::EntropyJump)) {
            return None;
        }
        let q = self.events.entry(pid).or_default();
        let directory = path.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
        q.push_back(Seen { ts, path: path.to_string(), directory, ext_changed: signals.contains(&Signal::ExtChanged) });
        while q.front().map(|f| ts - f.ts > self.window).unwrap_or(false) {
            q.pop_front();
        }
        let files: HashSet<&str> = q.iter().map(|e| e.path.as_str()).collect();
        let dirs: HashSet<&str> = q.iter().map(|e| e.directory.as_str()).collect();
        if files.len() >= self.min_files && dirs.len() >= self.min_dirs {
            let bonus = if q.iter().any(|e| e.ext_changed) { 0.1 } else { 0.0 };
            let conf = (0.6 + 0.04 * (files.len() - self.min_files) as f64 + bonus).min(0.99);
            let mut fl: Vec<String> = files.iter().map(|s| s.to_string()).collect();
            fl.sort();
            let secs = (ts - q.front().unwrap().ts) as i64;
            let v = Verdict {
                pid,
                confidence: (conf * 100.0).round() / 100.0,
                reasons: vec![format!("{} existing files overwritten with unrecognizable data in {}s", files.len(), secs), "original file signatures were destroyed".into()],
                files: fl,
            };
            self.fired.insert(pid);
            return Some(v);
        }
        None
    }

    pub fn reset(&mut self, pid: u32) {
        self.fired.remove(&pid);
        self.events.remove(&pid);
    }
}
