//! ETW real-time session on Microsoft-Windows-Kernel-File: gives every file event WITH the process that caused it.
//! Needs an elevated process (Administrator) or membership of "Performance Log Users"; without that StartTrace fails with ACCESS_DENIED.
//! Event ids/keywords were read from the provider manifest on this machine (`wevtutil gp Microsoft-Windows-Kernel-File /ge`):
//! 12 Create (0xa0) · 16 Write (0x220) · 26 DeletePath (0x400) · 27 RenamePath (0x800) · 30 CreateNewFile (0x1000).
use crate::guard::{DiskContent, FileEvent, Guard};
use crate::suspend;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

const SESSION: &str = "HalvardGuard";
const KEYWORDS: u64 = 0x80 | 0x200 | 0x400 | 0x800 | 0x1000; // create | write | delete | rename | create-new-file
const PROVIDER: GUID = GUID { data1: 0xEDD08927, data2: 0x9CC4, data3: 0x4E65, data4: [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89] };

struct State {
    guard: Guard,
    t0: Instant,
    events: u64,
    unreadable: u64,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A zeroed, 8-byte-aligned buffer holding EVENT_TRACE_PROPERTIES followed by the session name.
fn properties() -> (Vec<u64>, usize) {
    let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (SESSION.len() + 1) * 2;
    let mut buf = vec![0u64; (size + 7) / 8];
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = size as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1; // QPC timestamps
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    (buf, size)
}

pub fn stop_session() {
    let (mut buf, _) = properties();
    unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide(SESSION).as_ptr(), buf.as_mut_ptr() as *mut _, EVENT_TRACE_CONTROL_STOP) };
}

unsafe extern "system" fn ctrl_handler(_: u32) -> i32 {
    stop_session(); // makes ProcessTrace return so the session never outlives us
    1
}

fn image_name(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 520];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        full.rsplit('\\').next().unwrap_or("").to_string()
    }
}

unsafe fn prop_bytes(rec: *const EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let w = wide(name);
    let d = PROPERTY_DATA_DESCRIPTOR { PropertyName: w.as_ptr() as u64, ArrayIndex: u32::MAX, Reserved: 0 };
    let mut size = 0u32;
    if TdhGetPropertySize(rec, 0, null(), 1, &d, &mut size) != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if TdhGetProperty(rec, 0, null(), 1, &d, size, buf.as_mut_ptr()) != ERROR_SUCCESS {
        return None;
    }
    Some(buf)
}

unsafe fn prop_u64(rec: *const EVENT_RECORD, name: &str) -> Option<u64> {
    let b = prop_bytes(rec, name)?;
    let mut a = [0u8; 8];
    let n = b.len().min(8);
    a[..n].copy_from_slice(&b[..n]);
    Some(u64::from_le_bytes(a))
}

unsafe fn prop_str(rec: *const EVENT_RECORD, names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(b) = prop_bytes(rec, n) {
            let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
            return Some(String::from_utf16_lossy(&u));
        }
    }
    None
}


/// Names of every top-level string property this event type has, asked from Windows (TDH) instead of guessed.
unsafe fn string_property_names(rec: *const EVENT_RECORD) -> Vec<String> {
    let mut size = 0u32;
    TdhGetEventInformation(rec, 0, null(), null_mut(), &mut size);
    if size == 0 || size > 1 << 20 {
        return Vec::new();
    }
    let mut buf = vec![0u64; (size as usize + 7) / 8];
    let info = buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(rec, 0, null(), info, &mut size) != ERROR_SUCCESS {
        return Vec::new();
    }
    let base = buf.as_ptr() as *const u8;
    let n = (*info).TopLevelPropertyCount as usize;
    let arr = (*info).EventPropertyInfoArray.as_ptr();
    let mut out = Vec::new();
    for i in 0..n {
        let p = &*arr.add(i);
        if p.Flags & PropertyStruct != 0 {
            continue;
        }
        let in_type = p.Anonymous1.nonStructType.InType as i32;
        if in_type != TDH_INTYPE_UNICODESTRING && in_type != TDH_INTYPE_ANSISTRING {
            continue;
        }
        let name_ptr = base.add(p.NameOffset as usize) as *const u16;
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 && len < 128 {
            len += 1;
        }
        out.push(String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, len)));
    }
    out
}

/// Every string value of the event that looks like a path (delete and rename events name the file under different property names on different Windows builds).
unsafe fn path_values(rec: *const EVENT_RECORD) -> Vec<String> {
    let mut v = Vec::new();
    for name in string_property_names(rec) {
        if let Some(b) = prop_bytes(rec, &name) {
            let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
            let text = String::from_utf16_lossy(&u);
            if text.contains('\\') {
                v.push(text);
            }
        }
    }
    v
}

static DEBUG: AtomicBool = AtomicBool::new(false);
static DEBUG_SEEN: AtomicU32 = AtomicU32::new(0);

/// `guard --debug`: print what delete/rename/new-file events really contain, so property names can be confirmed from a real run.
unsafe fn debug_dump(rec: *const EVENT_RECORD, id: u16, pid: u32) {
    if !DEBUG.load(Ordering::Relaxed) || DEBUG_SEEN.fetch_add(1, Ordering::Relaxed) > 300 {
        return;
    }
    let props: Vec<String> = string_property_names(rec).iter().map(|n| format!("{n}={:?}", prop_str(rec, &[n.as_str()]).unwrap_or_default())).collect();
    crate::logsink::emit(&format!("{{\"debug\":{{\"event\":{id},\"pid\":{pid},\"properties\":{:?}}}}}", props));
}

unsafe extern "system" fn on_record(rec: *mut EVENT_RECORD) {
    let r = &*rec;
    let id = r.EventHeader.EventDescriptor.Id;
    let pid = r.EventHeader.ProcessId;
    if matches!(id, 26 | 27 | 30) {
        debug_dump(rec, id, pid);
    }
    let mut extra: Vec<FileEvent> = Vec::new();
    let ev = match id {
        12 => match (prop_u64(rec, "FileObject"), prop_str(rec, &["FileName"])) {
            (Some(obj), Some(name)) => Some(FileEvent::Open { pid, obj, name }),
            _ => None,
        },
        30 => match (prop_u64(rec, "FileObject"), prop_str(rec, &["FileName"])) {
            (Some(obj), Some(name)) => Some(FileEvent::NewFile { pid, obj, name }),
            _ => None,
        },
        16 => prop_u64(rec, "FileObject").map(|obj| FileEvent::Write { pid, obj }),
        26 | 27 => {
            // every path-looking string in the event (old and new name for a rename), whatever Windows calls the property
            let mut it = path_values(rec).into_iter().map(|name| if id == 26 { FileEvent::Delete { pid, name } } else { FileEvent::Rename { pid, name } });
            let first = it.next();
            extra.extend(it);
            first
        }
        _ => return,
    };
    let Ok(mut g) = STATE.lock() else { return };
    let Some(st) = g.as_mut() else { return };
    st.events += 1;
    let Some(ev) = ev else {
        st.unreadable += 1;
        return;
    };
    let frozen_now = std::iter::once(ev).chain(extra).filter_map(|e| st.guard.on_event(e)).next();
    if let Some(f) = frozen_now {
        let frozen = suspend::suspend(f.pid);
        let kind = if f.reason.starts_with("bulk encryption") { "bulk_encryption" } else { "tripwire" };
        crate::logsink::emit(&format!(
            "{{\"alert\":\"{kind}\",\"pid\":{},\"process\":{:?},\"path\":{:?},\"op\":\"{:?}\",\"frozen\":{},\"error\":{:?},\"reason\":{:?},\"t_ms\":{}}}",
            f.pid, f.process, f.path, f.op, frozen.is_ok(), frozen.err().unwrap_or_default(), f.reason, st.t0.elapsed().as_millis()
        ));
    }
}

/// Runs until Ctrl+C. Errors are plain sentences, including the elevation hint.
pub fn run(tripwires: Vec<String>, trust: Vec<String>, debug: bool) -> Result<(), String> {
    DEBUG.store(debug, Ordering::Relaxed);
    let mut guard = Guard::new(&tripwires, &trust, std::process::id(), Box::new({
        let cache: Mutex<HashMap<u32, String>> = Mutex::new(HashMap::new());
        move |pid| {
            let mut c = cache.lock().unwrap();
            if c.len() > 4096 {
                c.clear();
            }
            c.entry(pid).or_insert_with(|| image_name(pid)).clone()
        }
    }))
    .with_content(Box::new(DiskContent)); // turns the behavioral detector on
    // "before" pictures: remember the first bytes of the files in the folders that hold tripwires (those folders are what needs protecting)
    let mut warmed = 0;
    let mut seen_dirs = std::collections::HashSet::new();
    for t in &tripwires {
        if let Some(dir) = std::path::Path::new(t).parent().map(|p| p.to_string_lossy().to_string()) {
            if seen_dirs.insert(dir.to_lowercase()) {
                warmed += guard.warm(&dir, 50_000);
            }
        }
    }
    crate::logsink::emit(&format!("{{\"service\":\"warmed\",\"files\":{warmed}}}"));
    *STATE.lock().unwrap() = Some(State {
        guard,
        t0: Instant::now(),
        events: 0,
        unreadable: 0,
    });
    unsafe {
        let name = wide(SESSION);
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let (mut buf, _) = properties();
        let mut err = StartTraceW(&mut handle, name.as_ptr(), buf.as_mut_ptr() as *mut _);
        if err == ERROR_ALREADY_EXISTS {
            stop_session(); // a stale session from a killed run
            let (mut b2, _) = properties();
            err = StartTraceW(&mut handle, name.as_ptr(), b2.as_mut_ptr() as *mut _);
        }
        if err == ERROR_ACCESS_DENIED {
            return Err("access denied: run from an elevated (Administrator) PowerShell, or add this user to the 'Performance Log Users' group".into());
        }
        if err != ERROR_SUCCESS {
            return Err(format!("StartTrace failed: win32 error {err}"));
        }
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        let e = EnableTraceEx2(handle, &PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION as u8, KEYWORDS, 0, 0, null());
        if e != ERROR_SUCCESS {
            stop_session();
            return Err(format!("EnableTraceEx2 failed: win32 error {e}"));
        }
        let mut lf: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        lf.LoggerName = name.as_ptr() as *mut u16;
        lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.Anonymous2.EventRecordCallback = Some(on_record);
        lf.Context = null_mut::<c_void>();
        let th = OpenTraceW(&mut lf);
        if th.Value == u64::MAX {
            stop_session();
            return Err("OpenTrace failed".into());
        }
        println!("guarding {} tripwire(s) with ETW; a process that changes one is frozen. Ctrl+C to stop.", tripwires.len());
        let r = ProcessTrace(&th, 1, null(), null());
        CloseTrace(th);
        stop_session();
        if let Some(st) = STATE.lock().unwrap().as_ref() {
            println!("stopped. events seen {}, unreadable {}", st.events, st.unreadable);
        }
        if r != ERROR_SUCCESS {
            return Err(format!("ProcessTrace ended: win32 error {r}"));
        }
    }
    Ok(())
}
