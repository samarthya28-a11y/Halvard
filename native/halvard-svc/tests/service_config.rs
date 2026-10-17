//! Service configuration and command-line parsing (no service manager involved, so no elevation needed).
#![cfg(windows)]
use halvard_svc::service::{parse_install_args, Config};

fn a(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn install_args_become_a_config_and_round_trip_through_json() {
    let c = parse_install_args(&a(&["--tripwire", r"C:\Users\a\Documents\!000.xlsx", "--trust", "Backup.exe", "--tripwire", r"D:\Data\!000.docx"])).unwrap();
    assert_eq!(c.tripwires.len(), 2);
    assert_eq!(c.trust, vec!["Backup.exe"]);
    assert_eq!(Config::parse(&c.to_json()).unwrap(), c);
}

#[test]
fn relative_paths_unknown_options_and_empty_installs_are_refused() {
    assert!(parse_install_args(&a(&["--tripwire", r"docs\!000.xlsx"])).unwrap_err().contains("absolute"));
    assert!(parse_install_args(&a(&["--tripwire"])).is_err());
    assert!(parse_install_args(&a(&["--bogus", "x"])).unwrap_err().contains("unknown option"));
    assert!(parse_install_args(&a(&[])).unwrap_err().contains("at least one"));
}

#[test]
fn a_damaged_or_empty_config_is_refused_not_guessed() {
    assert!(Config::parse("not json").is_err());
    assert!(Config::parse(r#"{"version":2,"tripwires":["C:\\x"],"trust":[]}"#).unwrap_err().contains("version"));
    assert!(Config::parse(r#"{"version":1,"tripwires":[],"trust":[]}"#).unwrap_err().contains("no tripwires"));
    assert!(Config::parse(r#"{"version":1,"tripwires":[1],"trust":[]}"#).is_err());
    assert!(Config::parse(r#"{"version":1,"tripwires":["C:\\x"]}"#).is_err());
}

#[test]
fn log_file_rotates_instead_of_growing_forever() {
    let d = std::env::temp_dir().join(format!("halvard_log_{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("guard.log");
    std::fs::write(&f, vec![b'x'; 6 * 1024 * 1024]).unwrap(); // already over the 5 MB cap
    halvard_svc::logsink::set_file(f.clone());
    halvard_svc::logsink::emit("{\"t\":1}");
    assert!(d.join("guard.log.1").exists(), "old file kept as .1");
    assert!(std::fs::metadata(&f).unwrap().len() < 100, "new file starts small");
    let _ = std::fs::remove_dir_all(&d);
}
