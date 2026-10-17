//! Replays a sensor fixture (docs/25, `halvard/sensor.py`) through the brain. Same file format as the Python reference.
//! The replay keeps an in-memory model of each file's first 512 bytes (what the Python reference reads from disk), generates the same
//! deterministic bytes as `sensor.materialize`, and must reproduce the fixture's recorded `golden` decisions exactly.
use crate::brain::{Brain, Decision, Op, OpCtx};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub struct Fixture {
    pub header: Value,
    pub events: Vec<Value>,
}

pub fn load(path: &Path) -> Result<Fixture, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Value = serde_json::from_str(lines.next().ok_or("empty fixture")?).map_err(|e| e.to_string())?;
    if header["fixture"] != 1 {
        return Err(format!("unsupported fixture version {}", header["fixture"]));
    }
    let mut events = Vec::new();
    for l in lines {
        let e: Value = serde_json::from_str(l).map_err(|e| e.to_string())?;
        let op = e["op"].as_str().unwrap_or("");
        if Op::parse(op).is_none() {
            return Err(format!("unknown op {op:?}"));
        }
        events.push(e);
    }
    Ok(Fixture { header, events })
}

/// Same bytes as `sensor.materialize` in Python.
pub fn materialize(spec: &Value) -> Vec<u8> {
    let size = spec["size"].as_u64().unwrap_or(1000) as usize;
    let seed = spec["seed"].as_i64().unwrap_or(0);
    match spec["kind"].as_str().unwrap_or("text") {
        "random" => {
            let mut out = Vec::with_capacity(size + 32);
            let mut i = 0;
            while out.len() < size {
                out.extend_from_slice(&Sha256::digest(format!("{seed}:{i}").as_bytes()));
                i += 1;
            }
            out.truncate(size);
            out
        }
        "zeros" => vec![0u8; size],
        "magic" => {
            let mut v = vec![0xff, 0xd8, 0xff];
            for _ in 0..(size / 256 + 1) {
                v.extend(0u8..=255);
            }
            v.truncate(size);
            v
        }
        _ => {
            let unit = format!("Meeting notes {seed}. ").into_bytes();
            let mut v = Vec::new();
            for _ in 0..(size / 12 + 1) {
                v.extend_from_slice(&unit);
            }
            v.truncate(size);
            v
        }
    }
}

fn key(p: &str) -> String {
    crate::brain::key(p)
}

/// Returns (seq, allowed) for every event, and the brain afterwards.
pub fn run(fx: &Fixture) -> (Vec<(u64, bool)>, Brain) {
    let mut brain = Brain::new();
    if let Some(tws) = fx.header["tripwires"].as_array() {
        for t in tws {
            if let Some(p) = t["path"].as_str() {
                brain.add_tripwire(p);
            }
        }
    }
    // model of every file's first 512 bytes: seeded files, then updated by every allowed operation
    let mut heads: HashMap<String, Vec<u8>> = HashMap::new();
    if let Some(seed) = fx.header["seed_files"].as_array() {
        for (i, f) in seed.iter().enumerate() {
            let data = materialize(&serde_json::json!({"kind": f["kind"].as_str().unwrap_or("text"), "size": f["size"].as_u64().unwrap_or(3000), "seed": i}));
            heads.insert(key(f["path"].as_str().unwrap_or("")), data[..data.len().min(512)].to_vec());
        }
    }
    if let Some(tws) = fx.header["tripwires"].as_array() {
        for t in tws {
            heads.insert(key(t["path"].as_str().unwrap_or("")), b"decoy".to_vec()); // content is irrelevant: tripwires are judged by identity
        }
    }
    let name_of = |pid: u64| -> String { fx.header["processes"][pid.to_string()].as_str().unwrap_or("").to_string() };
    let mut out = Vec::new();
    for e in &fx.events {
        let pid = e["pid"].as_u64().unwrap_or(0);
        let op = Op::parse(e["op"].as_str().unwrap_or("")).unwrap();
        let path = e["path"].as_str().unwrap_or("");
        let dst = e["dst"].as_str();
        let now = e["t_ms"].as_f64().unwrap_or(0.0) / 1000.0;
        let data = if matches!(op, Op::Create | Op::Write) { Some(materialize(&e["data"])) } else { None };
        let before = heads.get(&key(path)).cloned();
        let ctx = OpCtx {
            now,
            pid: pid as u32,
            proc_name: &name_of(pid),
            op,
            path,
            dst,
            before_head: before.as_deref(),
            after_sample: data.as_deref().map(|d| &d[..d.len().min(4096)]),
        };
        let (decision, _verdict) = brain.on_op(&ctx);
        let allowed = decision == Decision::Allow;
        out.push((e["seq"].as_u64().unwrap_or(0), allowed));
        if allowed {
            // the operation happened: update the file model
            match op {
                Op::Create | Op::Write => {
                    let d = data.unwrap();
                    heads.insert(key(path), d[..d.len().min(512)].to_vec());
                }
                Op::Rename => {
                    if let Some(h) = heads.remove(&key(path)) {
                        heads.insert(key(dst.unwrap_or(path)), h);
                    }
                }
                Op::Delete => {
                    heads.remove(&key(path));
                }
                Op::Read => {}
            }
        }
    }
    (out, brain)
}

/// "AAAD..." for a replay result, comparable with a fixture's `golden`.
pub fn letters(res: &[(u64, bool)]) -> String {
    res.iter().map(|(_, a)| if *a { 'A' } else { 'D' }).collect()
}
