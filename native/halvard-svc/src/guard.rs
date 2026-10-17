//! Turns attributed file events (from ETW Microsoft-Windows-Kernel-File) into freeze decisions. Pure logic: no OS calls, fully unit-tested.
//! ETW Write events carry only a FileObject; Create events carry the name. `Guard` keeps the FileObject -> name map between them.
use crate::brain::{Brain, Decision, Op};
use std::collections::HashMap;

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
    pub reason: &'static str,
}

/// Processes that must never be frozen, whatever they touch: freezing them hangs the machine.
const NEVER_FREEZE: &[&str] = &["system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "dwm.exe", "svchost.exe"];
/// Trusted by default: the antivirus may legitimately quarantine a decoy.
const DEFAULT_TRUST: &[&str] = &["msmpeng.exe"];
const MAX_OBJECTS: usize = 100_000;

pub struct Guard {
    brain: Brain,
    objects: HashMap<u64, String>,
    own_pid: u32,
    name_of: Box<dyn Fn(u32) -> String + Send>,
    pub frozen: Vec<u32>,
}

impl Guard {
    pub fn new(tripwires: &[String], trust: &[String], own_pid: u32, name_of: Box<dyn Fn(u32) -> String + Send>) -> Guard {
        let mut brain = Brain::new();
        for t in tripwires {
            brain.add_tripwire(t);
        }
        for t in trust.iter().map(String::as_str).chain(DEFAULT_TRUST.iter().copied()) {
            brain.trust_name(t);
        }
        Guard { brain, objects: HashMap::new(), own_pid, name_of, frozen: Vec::new() }
    }

    fn remember(&mut self, obj: u64, name: &str) {
        if self.objects.len() >= MAX_OBJECTS {
            self.objects.clear(); // bounded memory beats a perfect map; a missed name only means a missed alert, reported as a gap by the service
        }
        self.objects.insert(obj, name.to_string());
    }

    fn judge(&mut self, pid: u32, op: Op, path: &str) -> Option<Freeze> {
        if pid == self.own_pid {
            return None;
        }
        let process = (self.name_of)(pid);
        match self.brain.decide(pid, &process, op, &[path]) {
            Decision::Deny { reason, newly_blocked: true } => {
                if NEVER_FREEZE.contains(&process.to_lowercase().as_str()) || pid <= 4 {
                    return None; // alert-only for protected system processes (the service reports it)
                }
                self.frozen.push(pid);
                Some(Freeze { pid, process, path: path.to_string(), op, reason })
            }
            _ => None,
        }
    }

    pub fn on_event(&mut self, ev: FileEvent) -> Option<Freeze> {
        match ev {
            FileEvent::Open { obj, name, .. } => {
                self.remember(obj, &name);
                None
            }
            FileEvent::NewFile { pid, obj, name } => {
                self.remember(obj, &name);
                self.judge(pid, Op::Create, &name)
            }
            FileEvent::Write { pid, obj } => {
                let name = self.objects.get(&obj).cloned()?;
                self.judge(pid, Op::Write, &name)
            }
            FileEvent::Delete { pid, name } => self.judge(pid, Op::Delete, &name),
            FileEvent::Rename { pid, name } => self.judge(pid, Op::Rename, &name),
        }
    }
}
