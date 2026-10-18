//! Turns attributed file events (from ETW Microsoft-Windows-Kernel-File) into freeze decisions. Logic only: file contents come through the
//! `Content` trait, so everything here is unit-tested with a fake. ETW Write events carry only a FileObject; Create events carry the name,
//! so `Guard` keeps the FileObject -> name map between them.
//!
//! Stage A limit, stated plainly: ETW tells us about a write AFTER it happened, so the "before" picture of a file is the first 512 bytes
//! remembered from earlier (warmed up at start-up for the folders that hold tripwires, refreshed by every benign write). A file never seen
//! before gives no "destroyed signature" signal; the tripwires and the other files of a burst still do the work.
use crate::brain::{key, Brain, Decision, Op, OpCtx};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    /// Event 12: a file was opened. Names the FileObject; says nothing about read or write.
    Open { pid: u32, obj: u64, name: String },
    /// Event 30: a new file was created (modifying).
    NewFile { pid: u32, obj: u64, name: String },
    /// Event 16: data written through a FileObject.
    Write { pid: u32, obj: u64 },
    /// Event 26 / 27: delete or rename, with the path in the event.
    Delete { pid: u32, name: String },
    Rename { pid: u32, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freeze {
    pub pid: u32,
    pub process: String,
    pub path: String,
    pub op: Op,
    pub reason: String,
}

/// Where file contents come from. The real one reads the disk; tests use a fake.
pub trait Content: Send {
    /// First `n` bytes of the file right now, or None if it cannot be read (missing, locked, denied).
    fn head(&self, path: &str, n: usize) -> Option<Vec<u8>>;
    /// Regular files directly or deeply under `dir` (bounded), used to warm the head cache.
    fn list(&self, _dir: &str, _limit: usize) -> Vec<String> {
        Vec::new()
    }
}

/// No contents available: only tripwire logic runs (what milestone M1 did).
pub struct NoContent;
impl Content for NoContent {
    fn head(&self, _: &str, _: usize) -> Option<Vec<u8>> {
        None
    }
}

/// Reads the real disk. ETW reports NT device paths (`\Device\HarddiskVolume3\...`), which Win32 opens through `\\?\GLOBALROOT`.
pub struct DiskContent;
impl DiskContent {
    fn win32(path: &str) -> String {
        if path.starts_with("\\Device\\") {
            format!("\\\\?\\GLOBALROOT{path}")
        } else {
            path.to_string()
        }
    }
}
impl Content for DiskContent {
    fn head(&self, path: &str, n: usize) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut f = std::fs::File::open(Self::win32(path)).ok()?;
        let mut buf = vec![0u8; n];
        let got = f.read(&mut buf).ok()?;
        buf.truncate(got);
        Some(buf)
    }
    fn list(&self, dir: &str, limit: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![(std::path::PathBuf::from(dir), 0u8)];
        while let Some((d, depth)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let Ok(t) = e.file_type() else { continue };
                if t.is_symlink() {
                    continue; // never follow links or junctions
                }
                if t.is_dir() && depth < 4 {
                    stack.push((e.path(), depth + 1));
                } else if t.is_file() {
                    out.push(e.path().to_string_lossy().to_string());
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }
}

/// Processes that must never be frozen, whatever they touch: freezing them hangs the machine. By NAME and, when the path is known, only if they really run
/// from the Windows folder: a program that merely calls itself svchost.exe in Downloads is not protected.
const NEVER_FREEZE: &[&str] = &["system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "dwm.exe", "svchost.exe"];
const WINDOWS_DIRS: &[&str] = &["\\windows\\system32\\", "\\windows\\syswow64\\"];
/// Trusted by default: the antivirus may legitimately quarantine a decoy. A name alone is not trust: it must run from one of its own install folders.
const DEFAULT_TRUST: &[(&str, &[&str])] = &[("msmpeng.exe", &["\\programdata\\microsoft\\windows defender\\", "\\program files\\windows defender\\", "\\program files\\microsoft security client\\"])];

fn lower(p: &str) -> String {
    p.replace('/', "\\").to_lowercase()
}
const MAX_OBJECTS: usize = 100_000;
const MAX_HEADS: usize = 200_000;
const HEAD: usize = 512;
const SAMPLE: usize = 4096;

pub struct Guard {
    brain: Brain,
    objects: HashMap<u64, String>,
    heads: HashMap<String, Vec<u8>>,
    content: Box<dyn Content>,
    t0: Instant,
    own_pid: u32,
    name_of: Box<dyn Fn(u32) -> String + Send>,
    path_of: Box<dyn Fn(u32) -> String + Send>,
    start_of: Box<dyn Fn(u32) -> u64 + Send>,
    starts: HashMap<u32, u64>,
    /// exact full image paths the owner trusts (`--trust C:\Tools\backup.exe`)
    trust_paths: Vec<String>,
    /// (file name, folders it must run from; empty = any folder, only for a name the owner chose explicitly)
    trust_rules: Vec<(String, Vec<String>)>,
    pub frozen: Vec<u32>,
}

impl Guard {
    /// `trust` entries containing a backslash or colon are exact image paths; anything else is a bare program name (explicit, owner-chosen, any folder).
    pub fn new(tripwires: &[String], trust: &[String], own_pid: u32, name_of: Box<dyn Fn(u32) -> String + Send>) -> Guard {
        let mut brain = Brain::new();
        for t in tripwires {
            brain.add_tripwire(t);
        }
        let mut trust_paths = Vec::new();
        let mut trust_rules: Vec<(String, Vec<String>)> = Vec::new();
        for t in trust {
            if t.contains('\\') || t.contains(':') {
                trust_paths.push(lower(t));
            } else {
                trust_rules.push((t.to_lowercase(), Vec::new()));
            }
        }
        for (n, dirs) in DEFAULT_TRUST {
            trust_rules.push((n.to_string(), dirs.iter().map(|d| d.to_string()).collect()));
        }
        Guard {
            brain,
            objects: HashMap::new(),
            heads: HashMap::new(),
            content: Box::new(NoContent),
            t0: Instant::now(),
            own_pid,
            name_of,
            path_of: Box::new(|_| String::new()),
            start_of: Box::new(|_| 0),
            starts: HashMap::new(),
            trust_paths,
            trust_rules,
            frozen: Vec::new(),
        }
    }

    /// Who a process really is: its full image path and when it started. The start time tells a reused process number from the program that had it before.
    pub fn with_identity(mut self, path_of: Box<dyn Fn(u32) -> String + Send>, start_of: Box<dyn Fn(u32) -> u64 + Send>) -> Guard {
        self.path_of = path_of;
        self.start_of = start_of;
        self
    }

    fn is_trusted(&self, name: &str, path: &str) -> bool {
        let (n, p) = (name.to_lowercase(), lower(path));
        self.trust_paths.iter().any(|t| *t == p) || self.trust_rules.iter().any(|(rn, dirs)| *rn == n && (dirs.is_empty() || (!p.is_empty() && dirs.iter().any(|d| p.contains(d.as_str())))))
    }

    fn is_protected(&self, name: &str, path: &str, pid: u32) -> bool {
        let (n, p) = (name.to_lowercase(), lower(path));
        pid <= 4 || (NEVER_FREEZE.contains(&n.as_str()) && (p.is_empty() || WINDOWS_DIRS.iter().any(|d| p.contains(d))))
    }

    /// Turn on the behavioral detector by giving the guard a way to read file contents.
    pub fn with_content(mut self, c: Box<dyn Content>) -> Guard {
        self.content = c;
        self
    }

    /// Remember the first bytes of the files under `dir` (bounded), so a later overwrite has a "before" picture.
    pub fn warm(&mut self, dir: &str, limit: usize) -> usize {
        let mut n = 0;
        for p in self.content.list(dir, limit) {
            if self.heads.len() >= MAX_HEADS {
                break;
            }
            if let Some(h) = self.content.head(&p, HEAD) {
                self.heads.insert(key(&p), h);
                n += 1;
            }
        }
        n
    }

    fn remember(&mut self, obj: u64, name: &str) {
        if self.objects.len() >= MAX_OBJECTS {
            self.objects.clear(); // bounded memory beats a perfect map; a missed name only means a missed alert, reported as a gap by the service
        }
        self.objects.insert(obj, name.to_string());
    }

    fn remember_head(&mut self, path: &str, head: Vec<u8>) {
        if self.heads.len() >= MAX_HEADS {
            self.heads.clear();
        }
        self.heads.insert(key(path), head);
    }

    fn judge(&mut self, pid: u32, op: Op, path: &str, dst: Option<&str>) -> Option<Freeze> {
        if pid == self.own_pid {
            return None;
        }
        let start = (self.start_of)(pid);      // first: it is what tells a reused process number from the program that had it, and lets the lookups below refresh
        let process = (self.name_of)(pid);
        let ipath = (self.path_of)(pid);
        if start != 0 {
            if self.starts.get(&pid).map(|old| *old != start).unwrap_or(false) {
                self.brain.forget(pid);            // same process number, different program: the old one's blocked state, history and freeze record do not apply
                self.frozen.retain(|p| *p != pid);
            }
            self.starts.insert(pid, start);
            if self.starts.len() > 20_000 { self.starts.clear(); }
        }
        let trusted = self.is_trusted(&process, &ipath);
        // contents: what the file looks like now (after a write or create), and what we remembered before
        let after = if matches!(op, Op::Write | Op::Create) { self.content.head(path, SAMPLE) } else { None };
        let before = self.heads.get(&key(path)).cloned();
        let ctx = OpCtx { now: self.t0.elapsed().as_secs_f64(), pid, proc_name: &process, trusted, op, path, dst, before_head: before.as_deref(), after_sample: after.as_deref() };
        let (decision, verdict) = self.brain.on_op(&ctx);
        // keep the cache current: the file now looks like `after`; a renamed file keeps its head under the new name
        match (op, &after) {
            (Op::Write | Op::Create, Some(a)) => self.remember_head(path, a[..a.len().min(HEAD)].to_vec()),
            (Op::Rename, _) => {
                if let Some(h) = self.heads.remove(&key(path)) {
                    self.remember_head(dst.unwrap_or(path), h);
                }
            }
            (Op::Delete, _) => {
                self.heads.remove(&key(path));
            }
            _ => {}
        }
        let (reason, newly) = match (decision, verdict) {
            (Decision::Deny { reason, newly_blocked: true }, _) => (reason.to_string(), true),
            (_, Some(v)) => (format!("bulk encryption: {}", v.reasons.join("; ")), true),
            _ => (String::new(), false),
        };
        if !newly {
            return None;
        }
        if self.is_protected(&process, &ipath, pid) {
            return None; // alert-only for protected system processes (the service reports it)
        }
        self.frozen.push(pid);
        Some(Freeze { pid, process, path: path.to_string(), op, reason })
    }

    pub fn on_event(&mut self, ev: FileEvent) -> Option<Freeze> {
        match ev {
            FileEvent::Open { obj, name, .. } => {
                self.remember(obj, &name);
                None
            }
            FileEvent::NewFile { pid, obj, name } => {
                self.remember(obj, &name);
                self.judge(pid, Op::Create, &name, None)
            }
            FileEvent::Write { pid, obj } => {
                let name = self.objects.get(&obj).cloned()?;
                self.judge(pid, Op::Write, &name, None)
            }
            FileEvent::Delete { pid, name } => self.judge(pid, Op::Delete, &name, None),
            FileEvent::Rename { pid, name } => self.judge(pid, Op::Rename, &name, None),
        }
    }

    /// A rename event that carries both names (old, new), when Windows provides them.
    pub fn on_rename(&mut self, pid: u32, old: &str, new: &str) -> Option<Freeze> {
        self.judge(pid, Op::Rename, old, Some(new))
    }
}
