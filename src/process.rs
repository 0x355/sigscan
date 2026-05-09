use crate::utils::wide_to_string;
use anyhow::{bail, Result};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

pub struct ProcessHandle(pub HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("No process matching '{0}' was found")]
    NotFound(String),
    #[error("Multiple processes named '{name}' found (PIDs: {pids:?}). Use a PID instead")]
    Ambiguous { name: String, pids: Vec<u32> },
}

pub fn find(target: &str) -> Result<ProcessInfo> {
    if let Ok(pid) = target.parse::<u32>() {
        find_by_pid(pid)
    } else {
        find_by_name(target)
    }
}

pub fn open(pid: u32) -> Result<ProcessHandle> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            0,
            pid,
        )
    };

    if handle.is_null() {
        let err = std::io::Error::last_os_error();
        bail!(
            "OpenProcess failed for PID {} -> {}\n\
            Hint: try running as Administrator for system processes.",
            pid,
            err
        );
    }

    Ok(ProcessHandle(handle))
}

fn find_by_pid(pid: u32) -> Result<ProcessInfo> {
    let entries = snapshot_processes()?;
    entries
        .into_iter()
        .find(|e| e.pid == pid)
        .ok_or_else(|| ProcessError::NotFound(pid.to_string()).into())
}

fn find_by_name(name: &str) -> Result<ProcessInfo> {
    let lower = name.to_lowercase();
    let mut matches: Vec<ProcessInfo> = snapshot_processes()?
        .into_iter()
        .filter(|e| e.name.to_lowercase() == lower)
        .collect();

    match matches.len() {
        0 => Err(ProcessError::NotFound(name.to_string()).into()),
        1 => Ok(matches.remove(0)),
        _ => {
            let pids: Vec<u32> = matches.iter().map(|e| e.pid).collect();
            Err(ProcessError::Ambiguous {
                name: name.to_string(),
                pids,
            }
            .into())
        }
    }
}

fn snapshot_processes() -> Result<Vec<ProcessInfo>> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        bail!("CreateToolhelp32Snapshot failed -> {}", err);
    }

    struct SnapGuard(HANDLE);
    impl Drop for SnapGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = SnapGuard(snap);

    let mut entries = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
        let err = std::io::Error::last_os_error();
        bail!("Process32FirstW failed -> {}", err);
    }

    loop {
        let name = wide_to_string(&entry.szExeFile);
        entries.push(ProcessInfo {
            pid: entry.th32ProcessID,
            name,
        });

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }

    Ok(entries)
}