//! Stage A decision logic: tripwires only. Mirrors `WardAgent.tripwire_gate` in the Python reference.
//! The bulk-encryption detector and the rest of the policy brain are ported in M2.
use std::collections::HashSet;

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
}

impl Brain {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_tripwire(&mut self, path: &str) {
        self.tripwires.insert(key(path));
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
