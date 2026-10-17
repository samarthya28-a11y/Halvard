//! Guard with file contents (behavioral detector on) and the detector's building blocks. A fake disk stands in for the real one.
use halvard_svc::detect::{classify, entropy, has_magic, Signal};
use halvard_svc::guard::{Content, FileEvent, Guard};
use halvard_svc::replay::materialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDisk(Arc<Mutex<HashMap<String, Vec<u8>>>>);
impl FakeDisk {
    fn put(&self, p: &str, d: Vec<u8>) {
        self.0.lock().unwrap().insert(p.to_string(), d);
    }
}
impl Content for FakeDisk {
    fn head(&self, path: &str, n: usize) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(path).map(|d| d[..d.len().min(n)].to_vec())
    }
    fn list(&self, dir: &str, limit: usize) -> Vec<String> {
        self.0.lock().unwrap().keys().filter(|k| k.starts_with(dir)).take(limit).cloned().collect()
    }
}

fn names(pid: u32) -> String {
    match pid {
        100 => "winword.exe".into(),
        200 => "burst.exe".into(),
        _ => String::new(),
    }
}
fn text(i: i64) -> Vec<u8> {
    materialize(&json!({"kind": "text", "size": 3000, "seed": i}))
}
fn random(i: i64) -> Vec<u8> {
    materialize(&json!({"kind": "random", "size": 3000, "seed": i}))
}
const DIR: &str = r"\Device\HarddiskVolume3\Users\a\Documents";
fn f(i: usize) -> String {
    format!("{DIR}\\file{i}.docx")
}

fn guard(disk: &FakeDisk) -> Guard {
    Guard::new(&[format!("{DIR}\\!000.xlsx")], &[], 1, Box::new(names)).with_content(Box::new(disk.clone()))
}

/// What ETW would deliver for "process pid overwrote file": an open of the file, then a write through that file object.
fn overwrite(g: &mut Guard, disk: &FakeDisk, pid: u32, obj: u64, path: &str, new: Vec<u8>) -> Option<halvard_svc::guard::Freeze> {
    g.on_event(FileEvent::Open { pid, obj, name: path.to_string() });
    disk.put(path, new); // by the time the event is delivered the new content is on disk
    g.on_event(FileEvent::Write { pid, obj })
}

#[test]
fn a_burst_of_overwrites_is_frozen_on_the_eighth_file_and_not_before() {
    let disk = FakeDisk::default();
    for i in 0..20 {
        disk.put(&f(i), text(i as i64));
    }
    let mut g = guard(&disk);
    assert_eq!(g.warm(DIR, 1000), 20, "before pictures remembered");
    for i in 0..7 {
        assert!(overwrite(&mut g, &disk, 200, i as u64, &f(i), random(i as i64)).is_none(), "file {i}: still under the threshold");
    }
    let fr = overwrite(&mut g, &disk, 200, 7, &f(7), random(7)).expect("eighth file must freeze");
    assert_eq!((fr.pid, fr.process.as_str()), (200, "burst.exe"));
    assert!(fr.reason.starts_with("bulk encryption"), "{}", fr.reason);
    assert!(overwrite(&mut g, &disk, 200, 8, &f(8), random(8)).is_none(), "already frozen: no second action");
    assert_eq!(g.frozen, vec![200]);
}

#[test]
fn normal_saves_by_a_word_processor_never_freeze_and_keep_the_cache_current() {
    let disk = FakeDisk::default();
    for i in 0..20 {
        disk.put(&f(i), text(i as i64));
    }
    let mut g = guard(&disk);
    g.warm(DIR, 1000);
    for round in 0..3 {
        for i in 0..20 {
            assert!(overwrite(&mut g, &disk, 100, (round * 100 + i) as u64, &f(i), text((i + round * 7) as i64 + 1000)).is_none());
        }
    }
    assert!(g.frozen.is_empty());
}

#[test]
fn without_a_before_picture_a_burst_is_not_detected_which_is_the_stage_a_limit() {
    let disk = FakeDisk::default(); // nothing warmed, files never seen before
    let mut g = guard(&disk);
    for i in 0..12 {
        assert!(overwrite(&mut g, &disk, 200, i as u64, &f(i), random(i as i64)).is_none());
    }
    assert!(g.frozen.is_empty(), "documented gap: unseen files give no 'destroyed signature' signal");
}

#[test]
fn copy_then_delete_style_is_frozen_through_delete_events() {
    let disk = FakeDisk::default();
    for i in 0..20 {
        disk.put(&f(i), text(i as i64));
    }
    let mut g = guard(&disk);
    g.warm(DIR, 1000);
    let mut frozen_at = None;
    for i in 0..20 {
        let enc = format!("{}.enc", f(i));
        disk.put(&enc, random(i as i64));
        g.on_event(FileEvent::NewFile { pid: 200, obj: 1000 + i as u64, name: enc });
        if g.on_event(FileEvent::Delete { pid: 200, name: f(i) }).is_some() {
            frozen_at = Some(i);
            break;
        }
    }
    assert_eq!(frozen_at, Some(7), "eighth original deleted");
}

#[test]
fn a_rename_with_both_names_is_judged_and_updates_the_cache() {
    let disk = FakeDisk::default();
    disk.put(&f(1), text(1));
    let mut g = guard(&disk);
    g.warm(DIR, 1000);
    assert!(g.on_rename(200, &f(1), &format!("{}.locked", f(1))).is_none(), "one rename is not a burst");
}

#[test]
fn detector_building_blocks_match_the_python_reference() {
    assert_eq!(entropy(b""), 0.0);
    assert_eq!(entropy(b"aaaa"), 0.0);
    assert!((entropy(b"abab") - 1.0).abs() < 1e-12);
    let all: Vec<u8> = (0u8..=255).collect();
    assert!((entropy(&all) - 8.0).abs() < 1e-12);
    assert!(has_magic(b"%PDF-1.7 ...") && has_magic(b"PK\x03\x04zzzz") && has_magic(b"plain readable text here"));
    assert!(!has_magic(&random(1)[..256]) && !has_magic(&[0u8; 64]) && !has_magic(b""));
    assert_eq!(classify(Some(&text(1)[..512]), &random(1)[..4096.min(3000)], false), vec![Signal::MagicDestroyed]);
    assert_eq!(classify(Some(&[0u8; 512]), &random(1), false), vec![Signal::EntropyJump]);
    assert_eq!(classify(None, &random(1), false), vec![]);
    assert_eq!(classify(Some(&text(1)[..512]), &text(2), false), vec![], "a normal save keeps its signature");
    assert_eq!(classify(Some(&text(1)[..512]), &text(2), true), vec![Signal::ExtChanged]);
}
