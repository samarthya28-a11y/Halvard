//! Guard: attributed ETW-style events -> freeze decisions. No OS access, so it runs unelevated.
use halvard_svc::brain::{key, Op};
use halvard_svc::guard::{FileEvent, Guard};

fn names(map: &'static [(u32, &'static str)]) -> Box<dyn Fn(u32) -> String + Send> {
    Box::new(move |pid| map.iter().find(|(p, _)| *p == pid).map(|(_, n)| n.to_string()).unwrap_or_default())
}

const TW: &str = r"C:\Users\a\Documents\!000-budget.xlsx";
const NT: &str = r"\Device\HarddiskVolume3\Users\a\Documents\!000-budget.xlsx"; // how ETW spells the same file

fn guard() -> Guard {
    Guard::new(&[TW.to_string()], &[], 1, names(&[(100, "burst.exe"), (200, "winword.exe"), (300, "backup.exe"), (400, "csrss.exe"), (500, "MsMpEng.exe")]))
}

#[test]
fn one_spelling_for_drive_letter_and_nt_device_paths() {
    assert_eq!(key(TW), key(NT));
    assert_eq!(key("docs/File.docx"), "docs/file.docx");
}

#[test]
fn a_write_through_a_tripwire_file_object_freezes_exactly_that_process_once() {
    let mut g = guard();
    assert!(g.on_event(FileEvent::Open { pid: 100, obj: 7, name: NT.into() }).is_none(), "opening alone proves nothing");
    let f = g.on_event(FileEvent::Write { pid: 100, obj: 7 }).expect("must freeze");
    assert_eq!((f.pid, f.process.as_str(), f.op), (100, "burst.exe", Op::Write));
    assert!(g.on_event(FileEvent::Write { pid: 100, obj: 7 }).is_none(), "already frozen: no second action");
    assert_eq!(g.frozen, vec![100]);
}

#[test]
fn writes_to_ordinary_files_and_to_unknown_file_objects_never_freeze() {
    let mut g = guard();
    g.on_event(FileEvent::Open { pid: 200, obj: 1, name: r"\Device\HarddiskVolume3\Users\a\Documents\report.docx".into() });
    assert!(g.on_event(FileEvent::Write { pid: 200, obj: 1 }).is_none());
    assert!(g.on_event(FileEvent::Write { pid: 200, obj: 999 }).is_none(), "name never seen: counted as a gap by the service, not a guess");
    assert!(g.frozen.is_empty());
}

#[test]
fn delete_rename_and_new_file_on_a_tripwire_freeze() {
    for ev in [
        FileEvent::Delete { pid: 100, name: NT.into() },
        FileEvent::Rename { pid: 100, name: NT.into() },
        FileEvent::NewFile { pid: 100, obj: 3, name: NT.into() },
    ] {
        assert!(guard().on_event(ev).is_some());
    }
}

#[test]
fn trusted_and_protected_processes_are_never_frozen_and_antivirus_is_trusted_by_default() {
    let mut g = Guard::new(&[TW.to_string()], &["Backup.exe".to_string()], 1, names(&[(300, "backup.exe"), (400, "csrss.exe"), (500, "MsMpEng.exe")]));
    for pid in [300, 400, 500] {
        assert!(g.on_event(FileEvent::Delete { pid, name: NT.into() }).is_none(), "pid {pid}");
    }
    assert!(g.frozen.is_empty());
}

#[test]
fn the_service_never_freezes_itself() {
    let mut g = Guard::new(&[TW.to_string()], &[], 100, names(&[(100, "halvard-svc.exe")]));
    assert!(g.on_event(FileEvent::Delete { pid: 100, name: NT.into() }).is_none());
}

#[test]
fn object_map_stays_bounded() {
    let mut g = guard();
    for i in 0..250_000u64 {
        g.on_event(FileEvent::Open { pid: 200, obj: i, name: "x".into() });
    }
    // still works after the map was recycled
    g.on_event(FileEvent::Open { pid: 100, obj: 9_999_999, name: NT.into() });
    assert!(g.on_event(FileEvent::Write { pid: 100, obj: 9_999_999 }).is_some());
}
