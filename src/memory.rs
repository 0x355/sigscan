use crate::{modules::ModuleInfo, process::ProcessHandle};
use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY, VirtualQueryEx,
        },
    },
};

const CHUNK_SIZE: usize = 0x10000;

pub fn read_module(handle: &ProcessHandle, module: &ModuleInfo) -> Result<Vec<u8>> {
    let total = module.size as usize;
    if total == 0 {
        bail!("Module '{}' reports zero size", module.name);
    }

    let mut buf = vec![0u8; total];
    let base = module.base;

    let mut cursor = 0usize;
    while cursor < total {
        let addr = base + cursor as u64;
        let remaining = total - cursor;

        if !page_is_readable(handle.0, addr) {
            cursor += CHUNK_SIZE;
            continue;
        }

        let chunk = remaining.min(CHUNK_SIZE);
        let mut bytes_read: usize = 0;

        let ok = unsafe {
            ReadProcessMemory(
                handle.0,
                addr as *const _,
                buf[cursor..cursor + chunk].as_mut_ptr() as *mut _,
                chunk,
                &mut bytes_read,
            )
        };

        if ok == 0 {
            buf[cursor..cursor + chunk].fill(0);
        }

        cursor += chunk;
    }

    Ok(buf)
}

fn page_is_readable(handle: HANDLE, addr: u64) -> bool {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let written = unsafe {
        VirtualQueryEx(
            handle,
            addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if written == 0 {
        return false;
    }

    if mbi.State != MEM_COMMIT {
        return false;
    }

    let prot = mbi.Protect & 0xFF;

    matches!(
        prot,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}
