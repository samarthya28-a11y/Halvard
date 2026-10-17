//! Windows service wrapper: install, uninstall, start, stop, status, and the service entry point.
//! Elevation: install, uninstall, start, stop need an Administrator PowerShell. `status` does not.
//! Security notes: the service runs as LocalSystem, so the executable is COPIED into Program Files (writable only by admins) and the config
//! folder in ProgramData is locked to admins/SYSTEM for writing; a binary in a user-writable folder would be a privilege-escalation hole.
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::define_windows_service;

pub const NAME: &str = "HalvardGuard";
const DISPLAY: &str = "Halvard Guard";
const DESCRIPTION: &str = "Halvard endpoint protection: freezes a program that changes a tripwire file. https://github.com/samarthya28-a11y/Halvard";

fn program_data() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("Halvard")
}
fn program_files() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into())).join("Halvard")
}
pub fn config_path() -> PathBuf {
    program_data().join("service.json")
}
pub fn log_path() -> PathBuf {
    program_data().join("guard.log")
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub tripwires: Vec<String>,
    pub trust: Vec<String>,
}

impl Config {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&json!({"version": 1, "tripwires": self.tripwires, "trust": self.trust})).unwrap()
    }
    pub fn parse(text: &str) -> Result<Config, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("config is not valid JSON: {e}"))?;
        if v["version"] != 1 {
            return Err(format!("unsupported config version {}", v["version"]));
        }
        let list = |k: &str| -> Result<Vec<String>, String> {
            v[k].as_array().ok_or(format!("'{k}' must be a list"))?.iter().map(|x| x.as_str().map(String::from).ok_or(format!("'{k}' must contain only text"))).collect()
        };
        let c = Config { tripwires: list("tripwires")?, trust: list("trust")? };
        if c.tripwires.is_empty() {
            return Err("config lists no tripwires: the guard would protect nothing".into());
        }
        Ok(c)
    }
}

/// `install --tripwire PATH ... [--trust name.exe ...]`
pub fn parse_install_args(args: &[String]) -> Result<Config, String> {
    let mut c = Config::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tripwire" => c.tripwires.push(it.next().ok_or("--tripwire needs a path")?.clone()),
            "--trust" => c.trust.push(it.next().ok_or("--trust needs a program name")?.clone()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    for t in &c.tripwires {
        if !Path::new(t).is_absolute() {
            return Err(format!("tripwire path must be absolute: {t}"));
        }
    }
    if c.tripwires.is_empty() {
        return Err("give at least one --tripwire <full path>".into());
    }
    Ok(c)
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(explain)
}

fn explain(e: windows_service::Error) -> String {
    let s = e.to_string();
    if let windows_service::Error::Winapi(io) = &e {
        match io.raw_os_error() {
            Some(5) => return "access denied: run this from an elevated (Administrator) PowerShell".into(),
            Some(1060) => return "the service is not installed".into(),
            Some(1073) => return "the service is already installed".into(),
            Some(1072) => return "the service is marked for deletion; close services.msc and retry, or reboot".into(),
            _ => {}
        }
    }
    s
}

pub fn install(cfg: &Config) -> Result<String, String> {
    let mgr = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    // 1. config folder, locked down
    let pd = program_data();
    std::fs::create_dir_all(&pd).map_err(|e| format!("cannot create {}: {e} (elevated PowerShell needed)", pd.display()))?;
    let _ = std::process::Command::new("icacls")
        .arg(&pd).args(["/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX"]).output();
    std::fs::write(config_path(), cfg.to_json()).map_err(|e| e.to_string())?;
    // 2. binary into Program Files
    let pf = program_files();
    std::fs::create_dir_all(&pf).map_err(|e| format!("cannot create {}: {e}", pf.display()))?;
    let target = pf.join("halvard-svc.exe");
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if me != target {
        std::fs::copy(&me, &target).map_err(|e| format!("cannot copy to {}: {e} (is the service running? stop it first)", target.display()))?;
    }
    // 3. the service
    let info = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from(DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target.clone(),
        launch_arguments: vec![OsString::from("service-run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS).map_err(explain)?;
    svc.set_description(DESCRIPTION).map_err(explain)?;
    svc.set_delayed_auto_start(true).map_err(explain)?; // does not slow boot
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })
    .map_err(explain)?;
    svc.set_failure_actions_on_non_crash_failures(true).map_err(explain)?;
    Ok(format!("installed {NAME}: auto-start (delayed), restarts itself after a failure, binary {}, config {}", target.display(), config_path().display()))
}

fn wait_for(svc: &windows_service::service::Service, want: ServiceState, secs: u64) -> Result<(), String> {
    for _ in 0..secs * 10 {
        if svc.query_status().map_err(explain)?.current_state == want {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("timed out waiting for the service to reach {want:?}"))
}

pub fn start() -> Result<String, String> {
    let svc = manager(ServiceManagerAccess::CONNECT)?.open_service(NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS).map_err(explain)?;
    svc.start::<OsString>(&[]).map_err(explain)?;
    wait_for(&svc, ServiceState::Running, 15)?;
    Ok("running".into())
}

pub fn stop() -> Result<String, String> {
    let svc = manager(ServiceManagerAccess::CONNECT)?.open_service(NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS).map_err(explain)?;
    if svc.query_status().map_err(explain)?.current_state != ServiceState::Stopped {
        svc.stop().map_err(explain)?;
    }
    wait_for(&svc, ServiceState::Stopped, 20)?;
    Ok("stopped".into())
}

pub fn status() -> Result<String, String> {
    let svc = manager(ServiceManagerAccess::CONNECT)?.open_service(NAME, ServiceAccess::QUERY_STATUS).map_err(explain)?;
    Ok(format!("{:?}", svc.query_status().map_err(explain)?.current_state))
}

pub fn uninstall() -> Result<String, String> {
    let _ = stop();
    let svc = manager(ServiceManagerAccess::CONNECT)?.open_service(NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS).map_err(explain)?;
    svc.delete().map_err(explain)?;
    drop(svc);
    let _ = std::fs::remove_file(program_files().join("halvard-svc.exe")); // may still be in use for a moment; harmless if it stays
    Ok(format!("uninstalled {NAME}. Logs and config were left in {} (delete the folder to remove them)", program_data().display()))
}

// ---------------- the service itself ----------------
define_windows_service!(ffi_service_main, service_main);

pub fn run_as_service() -> Result<(), String> {
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| format!("not started by the service manager: {e}"))
}

fn report(h: &service_control_handler::ServiceStatusHandle, state: ServiceState, accept: ServiceControlAccept, code: u32) {
    let _ = h.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    });
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = mpsc::channel::<()>();
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else { return };
    crate::logsink::set_file(log_path());
    let cfg = match std::fs::read_to_string(config_path()).map_err(|e| e.to_string()).and_then(|t| Config::parse(&t)) {
        Ok(c) => c,
        Err(e) => {
            crate::logsink::emit(&format!("{{\"service\":\"error\",\"why\":{:?}}}", format!("config: {e}")));
            report(&h, ServiceState::Stopped, ServiceControlAccept::empty(), 1);
            return;
        }
    };
    report(&h, ServiceState::StartPending, ServiceControlAccept::empty(), 0);
    let worker = std::thread::spawn(move || crate::etw::run(cfg.tripwires, cfg.trust));
    // Running only once the trace is really up: give it a moment, and report failure if the worker already ended.
    std::thread::sleep(Duration::from_millis(1500));
    if worker.is_finished() {
        let err = worker.join().ok().and_then(|r| r.err()).unwrap_or_else(|| "ended early".into());
        crate::logsink::emit(&format!("{{\"service\":\"error\",\"why\":{err:?}}}"));
        report(&h, ServiceState::Stopped, ServiceControlAccept::empty(), 2);
        return;
    }
    crate::logsink::emit("{\"service\":\"running\"}");
    report(&h, ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0);
    let _ = rx.recv(); // blocks until Stop or Shutdown
    report(&h, ServiceState::StopPending, ServiceControlAccept::empty(), 0);
    crate::etw::stop_session();
    let _ = worker.join();
    crate::logsink::emit("{\"service\":\"stopped\"}");
    report(&h, ServiceState::Stopped, ServiceControlAccept::empty(), 0);
}
