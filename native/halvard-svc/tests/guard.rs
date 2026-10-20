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
fn an_owner_trusted_name_and_a_protected_system_process_are_never_frozen() {
    // no path is known here: a name the owner chose explicitly is trusted; a protected system name with no known path is alert-only
    let mut g = Guard::new(&[TW.to_string()], &["Backup.exe".to_string()], 1, names(&[(300, "backup.exe"), (400, "csrss.exe")]));
    for pid in [300, 400] {
        assert!(g.on_event(FileEvent::Delete { pid, name: NT.into() }).is_none(), "pid {pid}");
    }
    assert!(g.frozen.is_empty());
}

#[test]
fn a_bare_antivirus_name_with_no_known_folder_is_not_trusted() {
    let mut g = Guard::new(&[TW.to_string()], &[], 1, names(&[(500, "MsMpEng.exe")]));
    assert!(g.on_event(FileEvent::Delete { pid: 500, name: NT.into() }).is_some(), "the name alone proves nothing");
}

#[test]
fn antivirus_under_its_own_folder_is_trusted_and_a_copy_of_svchost_outside_windows_is_not_protected() {
    let defender = r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe";
    let mut av = Guard::new(&[TW.to_string()], &[], 1, names(&[(500, "MsMpEng.exe")]))
        .with_identity(Box::new(|_| defender.to_string()), Box::new(|_| 0));
    assert!(av.on_event(FileEvent::Delete { pid: 500, name: NT.into() }).is_none());
    let fake = r"C:\Users\a\Downloads\svchost.exe";
    let mut g = Guard::new(&[TW.to_string()], &[], 1, names(&[(400, "svchost.exe")]))
        .with_identity(Box::new(|_| fake.to_string()), Box::new(|_| 0));
    assert!(g.on_event(FileEvent::Delete { pid: 400, name: NT.into() }).is_some(), "a known path outside Windows does not protect the name");
}

#[test]
fn an_explicit_image_path_is_trusted_only_at_that_path() {
    let good = r"C:\Tools\backup.exe";
    let mut g = Guard::new(&[TW.to_string()], &[good.to_string()], 1, names(&[(300, "backup.exe"), (301, "backup.exe")])).with_identity(
        Box::new(|pid| if pid == 300 { good.to_string() } else { r"C:\Users\a\Downloads\backup.exe".to_string() }),
        Box::new(|_| 0),
    );
    assert!(g.on_event(FileEvent::Delete { pid: 300, name: NT.into() }).is_none());
    assert!(g.on_event(FileEvent::Delete { pid: 301, name: NT.into() }).is_some());
}

#[test]
fn a_reused_pid_with_a_new_start_time_is_forgotten() {
    let start = std::sync::Arc::new(std::sync::Mutex::new(100u64));
    let clock = start.clone();
    let mut g = Guard::new(&[TW.to_string()], &[], 1, names(&[(100, "burst.exe")]))
        .with_identity(Box::new(|_| String::new()), Box::new(move |_| *clock.lock().unwrap()));
    assert!(g.on_event(FileEvent::Delete { pid: 100, name: NT.into() }).is_some());
    assert!(g.on_event(FileEvent::Delete { pid: 100, name: NT.into() }).is_none(), "still the same process");
    *start.lock().unwrap() = 200;
    assert!(g.on_event(FileEvent::Delete { pid: 100, name: NT.into() }).is_some(), "a new start time is a new process");
    assert_eq!(g.frozen, vec![100]);
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
