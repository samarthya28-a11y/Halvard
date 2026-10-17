//! The native brain must give the same answers as the Python reference on the shared fixtures (tests/fixtures/sensor).
//! M1 covers the tripwire brain only; the ransomware fixture needs the bulk-encryption detector (M2) and is checked to be NOT yet stopped, so M2 flips it.
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
fn ransomware_without_a_tripwire_is_not_stopped_until_the_detector_is_ported() {
    // Tripwires alone cannot stop this burst: the Python reference stops it with the behavioral detector (M2).
    let (res, _) = run(&load(&fixture("ransomware_overwrite_rename")).unwrap());
    assert!(res.iter().all(|(_, a)| *a), "if this fails the detector landed: update expectations to match the fixture header (max 20 changes)");
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
