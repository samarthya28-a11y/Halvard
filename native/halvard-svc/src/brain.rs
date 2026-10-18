//! Stage A decision logic: tripwires only. Mirrors `WardAgent.tripwire_gate` in the Python reference.
//! The bulk-encryption detector and the rest of the policy brain are ported in M2.
use crate::detect::{classify, entropy, has_magic, Detector, Signal, Verdict};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Write,
    Rename,
    Delete,
    Read,
}

impl Op {
    pub fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "create" => Op::Create,
            "write" => Op::Write,
            "rename" => Op::Rename,
            "delete" => Op::Delete,
            "read" => Op::Read,
            _ => return None,
        })
    }
    pub fn modifies(self) -> bool {
        !matches!(self, Op::Read)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// The process is now blocked; `suspend` is true when the first deny should freeze it.
    Deny { reason: &'static str, newly_blocked: bool },
}

/// Windows paths are case-insensitive and accept both separators: one key for every spelling.
/// Also drops a drive letter or an NT device prefix (`\Device\HarddiskVolume3\...`, what ETW reports), so `C:\x` and the kernel's spelling of it collide.
pub fn key(path: &str) -> String {
    let p = path.replace('\\', "/").to_lowercase();
    if let Some(rest) = p.strip_prefix("/device/harddiskvolume") {
        return rest.trim_start_matches(|c: char| c.is_ascii_digit()).to_string();
    }
    let b = p.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return p[2..].to_string();
    }
    p
}

#[derive(Default)]
pub struct Brain {
    tripwires: HashSet<String>,
    trusted_names: HashSet<String>,
    blocked: HashSet<u32>,
    detector: Detector,
    /// (time, path) of new files that look like random data, per process: the evidence behind "original replaced by a random-looking sibling" on delete.
    recent_highent: HashMap<u32, Vec<(f64, String)>>,
}

/// One file operation with the content facts the native sensor read (never stored): the old head (<= 512 bytes) and the new sample (<= 4096 bytes).
pub struct OpCtx<'a> {
    pub now: f64,
    pub pid: u32,
    pub proc_name: &'a str,
    /// decided by the caller from the process's identity (full path), not its name alone; the brain's own name list still applies for replayed fixtures
    pub trusted: bool,
    pub op: Op,
    pub path: &'a str,
    pub dst: Option<&'a str>,
    pub before_head: Option<&'a [u8]>,
    pub after_sample: Option<&'a [u8]>,
}

fn slashes(p: &str) -> String {
    p.replace('\\', "/")
}
fn dirname(p: &str) -> String {
    slashes(p).rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default()
}
fn basename(p: &str) -> String {
    slashes(p).rsplit('/').next().unwrap_or("").to_string()
}
/// Like Python's os.path.splitext: the extension of the last path part, never counting a leading dot.
fn splitext(p: &str) -> (String, String) {
    let b = basename(p);
    match b.rfind('.') {
        Some(i) if i > 0 && !b[..i].chars().all(|c| c == '.') => (b[..i].to_string(), b[i..].to_string()),
        _ => (b, String::new()),
    }
}

impl Brain {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_tripwire(&mut self, path: &str) {
        self.tripwires.insert(key(path));
    }
    /// A process number was reused by a different program: nothing known about the old one applies to the new one.
    pub fn forget(&mut self, pid: u32) {
        self.blocked.remove(&pid);
        self.detector.reset(pid);
        self.recent_highent.remove(&pid);
    }
    pub fn trust_name(&mut self, name: &str) {
        self.trusted_names.insert(name.to_lowercase());
    }
    pub fn is_blocked(&self, pid: u32) -> bool {
        self.blocked.contains(&pid)
    }
    pub fn blocked(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.blocked.iter().copied().collect();
        v.sort();
        v
    }

    /// Full judgement of one operation: tripwire gate first, then the behavioral detector. A detector verdict lets THIS operation stand (it already
    /// happened) and blocks the process from the next one on, exactly like the Python reference; the caller freezes the process when a verdict is returned.
    pub fn on_op(&mut self, c: &OpCtx) -> (Decision, Option<Verdict>) {
        if c.trusted {
            return (Decision::Allow, None); // the caller verified who this is (full path or the owner's explicit choice): neither the tripwire gate nor the detector applies
        }
        let mut paths = vec![c.path];
        paths.extend(c.dst);
        let d = self.decide(c.pid, c.proc_name, c.op, &paths);
        if d != Decision::Allow || self.trusted_names.contains(&c.proc_name.to_lowercase()) {
            return (d, None);
        }
        let path = slashes(c.path);
        let verdict = match c.op {
            Op::Create => {
                if let Some(a) = c.after_sample {
                    if a.len() >= 64 && !has_magic(&a[..a.len().min(256)]) && entropy(&a[..a.len().min(4096)]) > 7.5 {
                        self.recent_highent.entry(c.pid).or_default().push((c.now, path));
                    }
                }
                None
            }
            Op::Write => {
                let sig = match (c.before_head, c.after_sample) {
                    (Some(b), Some(a)) => classify(Some(b), &a[..a.len().min(4096)], false),
                    _ => Vec::new(),
                };
                self.detector.observe(c.now, c.pid, &path, &sig)
            }
            Op::Rename => {
                let dst = slashes(c.dst.unwrap_or(c.path));
                let changed = splitext(c.path).1 != splitext(&dst).1;
                let sig: Vec<Signal> = if changed { vec![Signal::ExtChanged] } else { vec![] };
                self.detector.observe(c.now, c.pid, &dst, &sig)
            }
            Op::Delete => {
                let stem = splitext(&path).0;
                let dir = dirname(&path);
                let hit = c.before_head.is_some()
                    && self.recent_highent.get(&c.pid).map(|hi| hi.iter().any(|(t, p)| c.now - t < 30.0 && dirname(p) == dir && basename(p).starts_with(&stem))).unwrap_or(false);
                let sig: Vec<Signal> = if hit { vec![Signal::MagicDestroyed] } else { vec![] };
                self.detector.observe(c.now, c.pid, &path, &sig)
            }
            Op::Read => None,
        };
        if verdict.is_some() {
            self.blocked.insert(c.pid);
        }
        (Decision::Allow, verdict)
    }

    /// `paths` are every path the operation touches (source and destination of a rename).
    pub fn decide(&mut self, pid: u32, proc_name: &str, op: Op, paths: &[&str]) -> Decision {
        if self.blocked.contains(&pid) {
            return Decision::Deny { reason: "process already stopped", newly_blocked: false };
        }
        if self.tripwires.is_empty() || self.trusted_names.contains(&proc_name.to_lowercase()) {
            return Decision::Allow;
        }
        let hit = paths.iter().any(|p| self.tripwires.contains(&key(p)));
        // Reading a tripwire is what indexers and backups do: counted elsewhere, never blocked.
        if hit && op.modifies() {
            self.blocked.insert(pid);
            return Decision::Deny { reason: "a tripwire file was changed before any real file was", newly_blocked: true };
        }
        Decision::Allow
    }
}
