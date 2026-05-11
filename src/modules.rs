use crate::utils::wide_to_string;
use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    },
};

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u32,
}

const ERROR_PARTIAL_COPY: i32 = 299;
const SNAPSHOT_RETRIES: u32 = 5;
const SNAPSHOT_RETRY_DELAY_MS: u64 = 50;

fn snapshot_modules(pid: u32) -> Result<windows_sys::Win32::Foundation::HANDLE> {
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    let mut last_err = std::io::Error::last_os_error();

    for _ in 0..SNAPSHOT_RETRIES {
        let snap = unsafe { CreateToolhelp32Snapshot(flags, pid) };
        if snap != INVALID_HANDLE_VALUE {
            return Ok(snap);
        }
        last_err = std::io::Error::last_os_error();
        if last_err.raw_os_error() != Some(ERROR_PARTIAL_COPY) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(SNAPSHOT_RETRY_DELAY_MS));
    }

    bail!(
        "CreateToolhelp32Snapshot(SNAPMODULE) failed for PID {} -> {}\n\
        Hint: the process may have exited, or you need Administrator rights.",
        pid,
        last_err
    );
}

pub fn enumerate(pid: u32) -> Result<Vec<ModuleInfo>> {
    let snap = snapshot_modules(pid)?;

    struct SnapGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for SnapGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = SnapGuard(snap);

    let mut modules = Vec::new();
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snap, &mut entry) } == 0 {
        let err = std::io::Error::last_os_error();
        bail!("Module32FirstW failed -> {}", err);
    }

    loop {
        modules.push(ModuleInfo {
            name: wide_to_string(&entry.szModule),
            base: entry.modBaseAddr as u64,
            size: entry.modBaseSize,
        });

        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if unsafe { Module32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }

    Ok(modules)
}
