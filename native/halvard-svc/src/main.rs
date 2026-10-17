use halvard_svc::{brain, replay};
use std::path::Path;

fn usage() {
    println!("halvard-svc {}\nUsage:\n  halvard-svc --version\n  halvard-svc replay <fixture.jsonl>\n  halvard-svc watch <folder> <tripwire-file-name>...   (alert only, no admin needed)
  halvard-svc guard <tripwire-full-path>... [--trust name.exe] [--debug]   (ETW, needs Administrator; freezes the offender; --debug dumps delete/rename event contents)
  halvard-svc status-report [--wait]   (what is running and what it caught, in plain words)
  halvard-svc stop   (stop a stale ETW session)
  halvard-svc service install --tripwire <full path>... [--trust name.exe]   (Administrator)
  halvard-svc service uninstall|start|stop   (Administrator)   |   service status (no admin)", halvard_svc::VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => println!("halvard-svc {}", halvard_svc::VERSION),
        Some("place") if args.len() >= 3 => {
            use halvard_svc::place as p;
            let (mut dir, mut names, mut manifest) = (None, Vec::new(), p::default_manifest());
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--dir" => dir = it.next().cloned(),
                    "--name" => names.extend(it.next().cloned()),
                    "--manifest" => manifest = it.next().map(std::path::PathBuf::from).unwrap_or(manifest),
                    o => {
                        eprintln!("error: unknown option {o}");
                        std::process::exit(2)
                    }
                }
            }
            let Some(dir) = dir else {
                eprintln!("error: --dir <folder> is required");
                std::process::exit(2)
            };
            if names.is_empty() {
                names = p::DEFAULT_NAMES.iter().map(|s| s.to_string()).collect();
            }
            match p::place(&dir, &names, &manifest) {
                Ok(r) => {
                    let mut created = Vec::new();
                    for x in r {
                        match x {
                            p::Placed::Created(path) => {
                                println!("created  {}", path.display());
                                created.push(path.display().to_string());
                            }
                            p::Placed::Skipped { path, why } => println!("skipped  {}  ({why})", path.display()),
                        }
                    }
                    println!("manifest {}", manifest.display());
                    if !created.is_empty() {
                        let t: Vec<String> = created.iter().map(|c| format!("--tripwire \"{c}\"")).collect();
                        println!("next: halvard-svc service install {}", t.join(" "));
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1)
                }
            }
        }
        Some("tripwires") if args.len() >= 2 => {
            use halvard_svc::place as p;
            let manifest = args.get(2).map(std::path::PathBuf::from).unwrap_or_else(p::default_manifest);
            match args[1].as_str() {
                "list" => {
                    for (path, st) in p::status(&manifest) {
                        println!("{:8} {path}", format!("{st:?}").to_lowercase());
                    }
                }
                "remove" => match p::remove(&manifest) {
                    Ok((r, l)) => {
                        r.iter().for_each(|x| println!("removed  {x}"));
                        l.iter().for_each(|x| println!("kept     {x}"));
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1)
                    }
                },
                _ => eprintln!("use: tripwires list|remove [manifest]"),
            }
        }
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
        Some("guard") if args.len() >= 2 => {
            let (mut tws, mut trust, mut debug) = (Vec::new(), Vec::new(), false);
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                if a == "--debug" {
                    debug = true;
                } else if a == "--trust" {
                    if let Some(n) = it.next() {
                        trust.push(n.clone());
                    }
                } else {
                    tws.push(a.clone());
                }
            }
            if let Err(e) = halvard_svc::etw::run(tws, trust, debug) {
                eprintln!("guard failed: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(windows)]
        Some("configure") | Some("unconfigure") => {
            use halvard_svc::service as s;
            let r = if args[0] == "unconfigure" {
                s::unconfigure()
            } else {
                let (mut dirs, mut trust) = (Vec::new(), Vec::new());
                let mut it = args[1..].iter();
                while let Some(a) = it.next() {
                    match a.as_str() {
                        // --dirs "C:\a;D:\b" (semicolon list, as the MSI property passes it; empty means every user's Documents)
                        "--dirs" => dirs.extend(it.next().map(|v| v.split(';').filter(|x| !x.trim().is_empty()).map(|x| x.trim().to_string()).collect::<Vec<_>>()).unwrap_or_default()),
                        "--dir" => dirs.extend(it.next().cloned()),
                        "--trust" => trust.extend(it.next().cloned()),
                        o => {
                            eprintln!("error: unknown option {o}");
                            std::process::exit(2)
                        }
                    }
                }
                s::configure(&dirs, &trust)
            };
            match r {
                Ok(m) => println!("{m}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1)
                }
            }
        }
        #[cfg(windows)]
        Some("status-report") => {
            println!("
{}", halvard_svc::service::status_page());
            if args.iter().any(|a| a == "--wait") {
                println!("Press Enter to close this window.");
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s);
            }
        }
        #[cfg(windows)]
        Some("stop") => halvard_svc::etw::stop_session(),
        #[cfg(windows)]
        Some("service-run") => {
            if let Err(e) = halvard_svc::service::run_as_service() {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        #[cfg(windows)]
        Some("service") if args.len() >= 2 => {
            use halvard_svc::service as s;
            let r = match args[1].as_str() {
                "install" => s::parse_install_args(&args[2..]).and_then(|c| s::install(&c)),
                "uninstall" => s::uninstall(),
                "start" => s::start(),
                "stop" => s::stop(),
                "status" => s::status(),
                "tune" => s::tune(),
                _ => Err("use: service install|uninstall|start|stop|status".into()),
            };
            match r {
                Ok(m) => println!("{m}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
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
