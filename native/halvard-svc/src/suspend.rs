//! Freeze and thaw a process: the Windows equivalent of SIGSTOP/SIGCONT used by the Linux reference.
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

type NtFn = unsafe extern "system" fn(HANDLE) -> i32;

fn call(pid: u32, name: &[u8]) -> Result<(), String> {
    // Never freeze ourselves or the System idle/System processes.
    if pid <= 4 || pid == std::process::id() {
        return Err(format!("refusing to touch pid {pid}"));
    }
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        let f = GetProcAddress(ntdll, name.as_ptr()).ok_or("ntdll function not found")?;
        let f: NtFn = std::mem::transmute::<unsafe extern "system" fn() -> isize, NtFn>(f);
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if h.is_null() {
            return Err(format!("OpenProcess failed: {}", GetLastError()));
        }
        let status = f(h);
        CloseHandle(h as *mut c_void);
        if status < 0 {
            return Err(format!("NTSTATUS {status:#x}"));
        }
    }
    Ok(())
}

pub fn suspend(pid: u32) -> Result<(), String> {
    call(pid, b"NtSuspendProcess\0")
}
pub fn resume(pid: u32) -> Result<(), String> {
    call(pid, b"NtResumeProcess\0")
}
