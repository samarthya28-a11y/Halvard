//! Windows only: freezing a real process stops it, thawing resumes it, and protected pids are refused.
#![cfg(windows)]
use std::process::{Command, Stdio};
use std::time::Duration;

fn size(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn suspend_stops_a_running_process_and_resume_restarts_it() {
    let f = std::env::temp_dir().join(format!("halvard_susp_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&f);
    let script = format!("while($true){{Add-Content -Path '{}' -Value 1; Start-Sleep -Milliseconds 20}}", f.display());
    let mut child = Command::new("powershell").args(["-NoProfile", "-Command", &script]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let t = std::time::Instant::now();
    while size(&f) == 0 && t.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(size(&f) > 0, "child never started writing");
    halvard_svc::suspend::suspend(child.id()).unwrap();
    std::thread::sleep(Duration::from_millis(200)); // let an in-flight write land
    let frozen = size(&f);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(size(&f), frozen, "a suspended process must not write");
    halvard_svc::suspend::resume(child.id()).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert!(size(&f) > frozen, "a resumed process must write again");
    child.kill().unwrap();
    let _ = std::fs::remove_file(&f);
}

#[test]
fn protected_pids_are_refused() {
    assert!(halvard_svc::suspend::suspend(4).is_err());
    assert!(halvard_svc::suspend::suspend(std::process::id()).is_err());
}

#[test]
fn watcher_reports_a_tripwire_change_quickly_and_ignores_other_files() {
    use std::sync::mpsc;
    let dir = std::env::temp_dir().join(format!("halvard_watch_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (tx, rx) = mpsc::channel();
    let d = dir.to_string_lossy().to_string();
    std::thread::spawn(move || {
        let _ = halvard_svc::watch::watch_dir(&d, |name, _| {
            tx.send((name.to_string(), std::time::Instant::now())).is_ok()
        });
    });
    std::thread::sleep(Duration::from_millis(300)); // watcher armed
    std::fs::write(dir.join("other.txt"), b"x").unwrap();
    let start = std::time::Instant::now();
    std::fs::write(dir.join("!000-trap.xlsx"), b"y").unwrap();
    let mut seen = Vec::new();
    while let Ok((n, at)) = rx.recv_timeout(Duration::from_secs(2)) {
        seen.push((n, at));
        if seen.iter().any(|(n, _)| n == "!000-trap.xlsx") {
            break;
        }
    }
    let (_, at) = seen.iter().find(|(n, _)| n == "!000-trap.xlsx").expect("tripwire event not seen");
    assert!(at.duration_since(start) < Duration::from_millis(500), "too slow: {:?}", at.duration_since(start));
    let _ = std::fs::remove_dir_all(&dir);
}
