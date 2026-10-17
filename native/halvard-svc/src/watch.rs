//! Directory watcher: one blocking ReadDirectoryChangesW call, so an idle watcher costs no CPU (no polling).
//! ReadDirectoryChangesW says WHAT changed, not WHO. Attribution to a process comes from ETW (M1b); until then a hit is an alert, not a stop.
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

pub const ADDED: u32 = 1;
pub const REMOVED: u32 = 2;
pub const MODIFIED: u32 = 3;
pub const RENAMED_OLD: u32 = 4;
pub const RENAMED_NEW: u32 = 5;

/// Calls `on_change(file_name, action)` for every change directly inside `dir`; returns only on error or when `on_change` returns false.
pub fn watch_dir(dir: &str, mut on_change: impl FnMut(&str, u32) -> bool) -> Result<(), u32> {
    let wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }
    let mut buf = vec![0u32; 16 * 1024]; // 64 KB, 4-byte aligned as the API requires
    let result = loop {
        let mut bytes = 0u32;
        let ok = unsafe {
            ReadDirectoryChangesW(
                h,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 4) as u32,
                0,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                &mut bytes,
                null_mut(),
                None,
            )
        };
        if ok == 0 {
            break Err(unsafe { GetLastError() });
        }
        if bytes == 0 {
            continue; // buffer overflow: events were lost; a real service would rescan and raise a coverage gap
        }
        let base = buf.as_ptr() as *const u8;
        let mut off = 0usize;
        let mut keep = true;
        loop {
            // FILE_NOTIFY_INFORMATION { NextEntryOffset: u32, Action: u32, FileNameLength: u32 (bytes), FileName: [u16] }
            let rec = unsafe { base.add(off) };
            let next = unsafe { *(rec as *const u32) } as usize;
            let action = unsafe { *(rec.add(4) as *const u32) };
            let len = unsafe { *(rec.add(8) as *const u32) } as usize / 2;
            let name = unsafe { std::slice::from_raw_parts(rec.add(12) as *const u16, len) };
            keep = on_change(&String::from_utf16_lossy(name), action) && keep;
            if next == 0 {
                break;
            }
            off += next;
        }
        if !keep {
            break Ok(());
        }
    };
    unsafe { CloseHandle(h) };
    result
}
