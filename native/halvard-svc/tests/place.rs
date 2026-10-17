//! Tripwire placement safety. Uses real folders under the user's temp directory (no elevation needed) and a real NTFS junction.
use halvard_svc::place::*;
use std::path::{Path, PathBuf};

fn work(name: &str) -> PathBuf {
    // %TEMP% sits under AppData\Local, which is a perfectly valid folder for these tests.
    let d = std::env::temp_dir().join(format!("halvard_place_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().map(|c| PathBuf::from(c.to_string_lossy().trim_start_matches(r"\\?\"))).unwrap()
}
fn s(p: &Path) -> String {
    p.to_string_lossy().to_string()
}
fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn creates_bland_decoys_and_records_their_hash() {
    let d = work("create");
    let m = d.join("m.json");
    let r = place(&s(&d), &names(&["!000-budget-draft.xlsx", "!000-notes.pdf", "!000-plain.txt"]), &m).unwrap();
    assert_eq!(r.len(), 3);
    let x = std::fs::read(d.join("!000-budget-draft.xlsx")).unwrap();
    assert!(x.starts_with(b"PK\x03\x04"), "an xlsx decoy looks like one");
    assert!(std::fs::read(d.join("!000-notes.pdf")).unwrap().starts_with(b"%PDF-1.4"));
    for f in ["!000-budget-draft.xlsx", "!000-notes.pdf", "!000-plain.txt"] {
        let t = String::from_utf8_lossy(&std::fs::read(d.join(f)).unwrap()).to_lowercase();
        assert!(!t.contains("halvard") && !t.contains("honeypot") && !t.contains("tripwire") && !t.contains("decoy"), "{f} must not give itself away");
    }
    assert!(status(&m).iter().all(|(_, st)| *st == State::Ok));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn never_replaces_an_existing_file() {
    let d = work("exists");
    let m = d.join("m.json");
    std::fs::write(d.join("!000-budget-draft.xlsx"), b"my real budget").unwrap();
    let r = place(&s(&d), &names(&["!000-budget-draft.xlsx"]), &m).unwrap();
    assert!(matches!(&r[0], Placed::Skipped { why, .. } if why.contains("never replaces")));
    assert_eq!(std::fs::read(d.join("!000-budget-draft.xlsx")).unwrap(), b"my real budget");
    assert!(status(&m).is_empty(), "nothing was created, so nothing is in the manifest (and nothing could ever be deleted)");
    // a second run over our own decoy also leaves it alone
    place(&s(&d), &names(&["!000-two.docx"]), &m).unwrap();
    let before = std::fs::read(d.join("!000-two.docx")).unwrap();
    let r2 = place(&s(&d), &names(&["!000-two.docx"]), &m).unwrap();
    assert!(matches!(r2[0], Placed::Skipped { .. }));
    assert_eq!(std::fs::read(d.join("!000-two.docx")).unwrap(), before);
    assert_eq!(status(&m).len(), 1, "no duplicate manifest entry");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn refuses_system_network_relative_root_and_missing_folders() {
    let m = work("refuse").join("m.json");
    for bad in [
        r"C:\Windows", r"C:\Windows\System32", r"c:\program files\x", r"C:\Program Files (x86)", r"C:\ProgramData\x", r"C:\$Recycle.Bin",
        r"\\server\share\docs", r"\\?\C:\Users\a", r"C:\", r"C:", r"docs", r"..\docs", r"C:\Users\a\..\..\Windows", r"/etc",
    ] {
        assert!(place(bad, &names(&["!000-a.xlsx"]), &m).is_err(), "must refuse {bad}");
    }
    let e = place(r"C:\this\folder\does\not\exist", &names(&["!000-a.xlsx"]), &m).unwrap_err();
    assert!(e.contains("does not exist"));
}

#[test]
fn refuses_unsafe_names_and_types() {
    let d = work("names");
    let m = d.join("m.json");
    for bad in [r"..\x.xlsx", r"sub\x.xlsx", "x.xlsx.", "x.xlsx ", "x.exe", "x.ps1", "noext", "", "a:b.xlsx", "x.xlsx:stream"] {
        assert!(place(&s(&d), &names(&[bad]), &m).is_err(), "must refuse {bad:?}");
    }
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "nothing was created");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn refuses_a_folder_reached_through_a_junction() {
    let d = work("junction");
    let real = d.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = d.join("link");
    let ok = std::process::Command::new("cmd").args(["/c", "mklink", "/J", &s(&link), &s(&real)]).output().unwrap().status.success();
    assert!(ok, "could not create a junction for the test");
    let e = place(&s(&link), &names(&["!000-a.xlsx"]), &d.join("m.json")).unwrap_err();
    assert!(e.contains("link or junction"), "{e}");
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0, "nothing was created in the junction target");
    let _ = std::process::Command::new("cmd").args(["/c", "rmdir", &s(&link)]).output();
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn remove_deletes_only_what_is_still_ours() {
    let d = work("remove");
    let m = d.join("m.json");
    place(&s(&d), &names(&["!000-a.xlsx", "!000-b.docx", "!000-c.txt"]), &m).unwrap();
    std::fs::write(d.join("!000-b.docx"), b"the user edited this").unwrap(); // changed since placed
    std::fs::remove_file(d.join("!000-c.txt")).unwrap(); // already gone
    let st = status(&m);
    assert_eq!(st.iter().filter(|(_, x)| *x == State::Changed).count(), 1);
    assert_eq!(st.iter().filter(|(_, x)| *x == State::Missing).count(), 1);
    let (removed, left) = remove(&m).unwrap();
    assert_eq!(removed.len(), 2);
    assert_eq!(left.len(), 1);
    assert!(!d.join("!000-a.xlsx").exists());
    assert_eq!(std::fs::read(d.join("!000-b.docx")).unwrap(), b"the user edited this", "an edited file is never deleted");
    assert_eq!(status(&m).len(), 1, "the kept file stays listed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn decoys_are_deterministic_per_folder_and_differ_between_files() {
    assert_eq!(decoy_bytes("a", "xlsx"), decoy_bytes("a", "xlsx"));
    assert_ne!(decoy_bytes("a", "xlsx"), decoy_bytes("b", "xlsx"));
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn placed_files_sort_before_ordinary_names() {
    let mut v = vec!["Annual report.docx", "budget.xlsx", "!000-budget-draft.xlsx", "Zebra.pdf", "_x.txt"];
    v.sort_by_key(|x| x.to_lowercase());
    assert_eq!(v[0], "!000-budget-draft.xlsx");
    for n in DEFAULT_NAMES {
        assert!(n.starts_with("!000"));
    }
}
