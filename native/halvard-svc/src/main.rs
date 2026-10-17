use halvard_svc::{brain, replay};
use std::path::Path;

fn usage() {
    println!("halvard-svc {}\nUsage:\n  halvard-svc --version\n  halvard-svc replay <fixture.jsonl>\n  halvard-svc watch <folder> <tripwire-file-name>...", halvard_svc::VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => println!("halvard-svc {}", halvard_svc::VERSION),
        Some("replay") if args.len() == 2 => {
            let fx = match replay::load(Path::new(&args[1])) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2)
                }
            };
            let (res, b) = replay::run(&fx);
            let allowed = res.iter().filter(|(_, a)| *a).count();
            let first_deny = res.iter().find(|(_, a)| !*a).map(|(s, _)| *s);
            println!("events {} allowed {} denied {} first_deny_seq {:?} blocked {:?}", res.len(), allowed, res.len() - allowed, first_deny, b.blocked());
        }
        #[cfg(windows)]
        Some("watch") if args.len() >= 3 => {
            let dir = args[1].clone();
            let mut b = brain::Brain::new();
            for t in &args[2..] {
                b.add_tripwire(t);
            }
            let t0 = std::time::Instant::now();
            let mut n: u32 = 0;
            println!("watching {dir} for {} tripwire(s); pid attribution needs ETW (M1b), so hits are alerts only", args.len() - 2);
            let r = halvard_svc::watch::watch_dir(&dir, |name, action| {
                // The watcher cannot see the process; each event gets a throwaway pid (u32::MAX - n), never a real one, so nothing is frozen.
                let op = match action {
                    halvard_svc::watch::REMOVED => brain::Op::Delete,
                    halvard_svc::watch::ADDED => brain::Op::Create,
                    halvard_svc::watch::RENAMED_OLD | halvard_svc::watch::RENAMED_NEW => brain::Op::Rename,
                    _ => brain::Op::Write,
                };
                if let brain::Decision::Deny { reason, .. } = { n += 1; b.decide(u32::MAX - n, "", op, &[name]) } {
                    println!("{{\"alert\":\"tripwire\",\"file\":{:?},\"action\":{},\"reason\":{:?},\"t_ms\":{}}}", name, action, reason, t0.elapsed().as_millis());
                }
                true
            });
            if let Err(code) = r {
                eprintln!("watch failed: win32 error {code}");
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
}
