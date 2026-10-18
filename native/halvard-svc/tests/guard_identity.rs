//! Who a process really is: trust and protection by full image path, and process numbers that get reused. (Independent review, 2026-10-17.)
use halvard_svc::guard::{FileEvent, Guard};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const TW: &str = r"C:\Users\a\Documents\!000-budget.xlsx";
const NT: &str = r"\Device\HarddiskVolume3\Users\a\Documents\!000-budget.xlsx";

/// A fake process table: pid -> (name, full path, start time). Shared so a test can change what a pid means mid-run (reuse).
type Table = Arc<Mutex<HashMap<u32, (String, String, u64)>>>;

fn table(rows: &[(u32, &str, &str, u64)]) -> Table {
    Arc::new(Mutex::new(rows.iter().map(|(p, n, path, s)| (*p, (n.to_string(), path.to_string(), *s))).collect()))
}

fn guard(t: &Table, trust: &[&str]) -> Guard {
    let (a, b, c) = (t.clone(), t.clone(), t.clone());
    let trust: Vec<String> = trust.iter().map(|s| s.to_string()).collect();
    Guard::new(&[TW.to_string()], &trust, 1, Box::new(move |p| a.lock().unwrap().get(&p).map(|r| r.0.clone()).unwrap_or_default()))
        .with_identity(Box::new(move |p| b.lock().unwrap().get(&p).map(|r| r.1.clone()).unwrap_or_default()), Box::new(move |p| c.lock().unwrap().get(&p).map(|r| r.2).unwrap_or(0)))
}

fn touch(g: &mut Guard, pid: u32) -> bool {
    g.on_event(FileEvent::Delete { pid, name: NT.into() }).is_some()
}

#[test]
fn the_real_antivirus_is_trusted_but_a_program_that_only_uses_its_name_is_not() {
    let t = table(&[
        (10, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3-0\MsMpEng.exe", 1),
        (11, "MsMpEng.exe", r"C:\Users\a\Downloads\MsMpEng.exe", 1),
        (12, "MsMpEng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe", 1),
    ]);
    let mut g = guard(&t, &[]);
    assert!(!touch(&mut g, 10), "the real one, from its own folder");
    assert!(!touch(&mut g, 12));
    assert!(touch(&mut g, 11), "a look-alike in Downloads is just a program that touched a tripwire");
}

#[test]
fn a_fake_system_process_name_in_the_wrong_folder_is_not_protected_but_the_real_one_is() {
    let t = table(&[(20, "svchost.exe", r"C:\Windows\System32\svchost.exe", 1), (21, "svchost.exe", r"C:\Users\a\AppData\Local\Temp\svchost.exe", 1), (22, "lsass.exe", "", 1)]);
    let mut g = guard(&t, &[]);
    assert!(!touch(&mut g, 20), "the real service host is alert-only");
    assert!(!touch(&mut g, 22), "path unknown (a protected process cannot be opened): stay safe");
    assert!(touch(&mut g, 21), "a program in Temp that calls itself svchost.exe gets no immunity");
}

#[test]
fn trust_by_exact_path_and_by_explicit_name() {
    let t = table(&[(30, "backup.exe", r"C:\Tools\Backup\backup.exe", 1), (31, "backup.exe", r"C:\Users\a\Downloads\backup.exe", 1), (32, "sync.exe", r"D:\anywhere\sync.exe", 1)]);
    let mut g = guard(&t, &[r"C:\Tools\Backup\backup.exe", "sync.exe"]);
    assert!(!touch(&mut g, 30), "exact path trusted");
    assert!(touch(&mut g, 31), "same name, other folder: not trusted when the owner gave a path");
    assert!(!touch(&mut g, 32), "a bare name the owner typed is trusted wherever it runs (their explicit choice)");
}

#[test]
fn a_reused_process_number_does_not_inherit_the_old_programs_fate() {
    let t = table(&[(40, "burst.exe", r"C:\Users\a\Downloads\burst.exe", 100)]);
    let mut g = guard(&t, &[]);
    assert!(touch(&mut g, 40), "frozen");
    assert!(!touch(&mut g, 40), "still the same program: no second action");
    assert_eq!(g.frozen, vec![40]);
    // the frozen program is killed and Windows hands number 40 to a different program, started later
    t.lock().unwrap().insert(40, ("winword.exe".into(), r"C:\Program Files\Office\winword.exe".into(), 900));
    let ev = g.on_event(FileEvent::Delete { pid: 40, name: format!("{}\\scratch.tmp", r"\Device\HarddiskVolume3\Users\a\Documents") });
    assert!(ev.is_none(), "an ordinary delete by the new program is just an ordinary delete");
    assert!(!g.frozen.contains(&40), "the freeze record belongs to the old program");
    // and the new one is judged on its own behaviour: touching a tripwire freezes it again, as a fresh decision
    assert!(touch(&mut g, 40));
}
