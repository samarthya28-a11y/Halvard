//! The native brain must give the same answers as the Python reference on the shared fixtures (tests/fixtures/sensor).
//! M1 covered the tripwire brain; M2 adds the bulk-encryption detector, so the ransomware fixture is now stopped too.
use halvard_svc::replay::{load, run};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sensor").join(format!("{name}.jsonl"))
}

#[test]
fn tripwire_first_touch_denies_event_one_and_everything_after() {
    let fx = load(&fixture("tripwire_first_touch")).unwrap();
    let (res, brain) = run(&fx);
    assert_eq!(res.iter().find(|(_, a)| !*a).map(|(s, _)| *s), Some(1));
    assert!(res.iter().all(|(_, a)| !*a), "no real file may change");
    assert_eq!(brain.blocked(), vec![4243]);
}

#[test]
fn benign_office_session_is_never_blocked() {
    let (res, brain) = run(&load(&fixture("benign_office_session")).unwrap());
    assert!(res.iter().all(|(_, a)| *a));
    assert!(brain.blocked().is_empty());
}

#[test]
fn benign_compressor_is_never_blocked() {
    let (res, brain) = run(&load(&fixture("benign_compressor")).unwrap());
    assert!(res.iter().all(|(_, a)| *a));
    assert!(brain.blocked().is_empty());
}

#[test]
fn ransomware_is_stopped_after_eight_files_exactly_like_the_python_reference() {
    let fx = load(&fixture("ransomware_overwrite_rename")).unwrap();
    let (res, brain) = run(&fx);
    let allowed = res.iter().filter(|(_, a)| *a).count();
    assert_eq!(allowed, 15, "8 overwrites and 7 renames happen, then the process is stopped");
    assert_eq!(res.iter().find(|(_, a)| !*a).map(|(s, _)| *s), Some(16));
    assert_eq!(brain.blocked(), vec![4242]);
}

#[test]
fn every_fixture_reproduces_the_golden_decisions_recorded_from_the_python_reference() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sensor");
    let mut n = 0;
    for f in std::fs::read_dir(dir).unwrap().flatten().filter(|f| f.path().extension().map(|e| e == "jsonl").unwrap_or(false)) {
        let fx = load(&f.path()).unwrap();
        let (res, _) = run(&fx);
        assert_eq!(halvard_svc::replay::letters(&res), fx.header["golden"].as_str().unwrap(), "{}", f.path().display());
        n += 1;
    }
    assert!(n >= 9, "expected all nine shipped fixtures, saw {n}");
}

#[test]
fn trusted_process_may_touch_a_tripwire_and_reads_never_block() {
    use halvard_svc::brain::{Brain, Decision, Op};
    let mut b = Brain::new();
    b.add_tripwire(r"C:\Users\a\Docs\!000.xlsx");
    b.trust_name("Backup.exe");
    assert_eq!(b.decide(5, "backup.exe", Op::Write, &["c:/users/a/docs/!000.xlsx"]), Decision::Allow);
    assert_eq!(b.decide(6, "indexer.exe", Op::Read, &["C:/Users/A/DOCS/!000.XLSX"]), Decision::Allow);
    assert!(matches!(b.decide(7, "x.exe", Op::Rename, &[r"c:\users\a\docs\other.txt", r"C:\USERS\A\DOCS\!000.xlsx"]), Decision::Deny { newly_blocked: true, .. }));
    assert!(matches!(b.decide(7, "x.exe", Op::Read, &["anything"]), Decision::Deny { newly_blocked: false, .. }));
}

#[test]
fn bad_fixtures_are_refused() {
    let d = std::env::temp_dir().join("halvard_bad_fixture.jsonl");
    std::fs::write(&d, "{\"fixture\":2}\n").unwrap();
    assert!(load(&d).is_err());
    std::fs::write(&d, "{\"fixture\":1}\n{\"seq\":1,\"op\":\"chmod\",\"pid\":1,\"path\":\"a\"}\n").unwrap();
    assert!(load(&d).is_err());
}
