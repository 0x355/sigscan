use crate::utils::wide_to_string;
use anyhow::{bail, Result};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    },
};

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u32,
}

pub fn enumerate(pid: u32) -> Result<Vec<ModuleInfo>> {
    let snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    };

    if snap == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        bail!(
            "CreateToolhelp32Snapshot(SNAPMODULE) failed for PID {} -> {}\n\
            Hint: the process may have exited, or you need Administrator rights.",
            pid,
            err
        );
    }

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