//! Replays a sensor fixture (docs/25, `halvard/sensor.py`) through the brain. Same file format as the Python reference.
use crate::brain::{Brain, Decision, Op};
use serde_json::Value;
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
    let name_of = |pid: u64| -> String {
        fx.header["processes"][pid.to_string()].as_str().unwrap_or("").to_string()
    };
    let mut out = Vec::new();
    for e in &fx.events {
        let pid = e["pid"].as_u64().unwrap_or(0);
        let op = Op::parse(e["op"].as_str().unwrap_or("")).unwrap();
        let mut paths = vec![e["path"].as_str().unwrap_or("")];
        if let Some(d) = e["dst"].as_str() {
            paths.push(d);
        }
        let d = brain.decide(pid as u32, &name_of(pid), op, &paths);
        out.push((e["seq"].as_u64().unwrap_or(0), d == Decision::Allow));
    }
    (out, brain)
}
