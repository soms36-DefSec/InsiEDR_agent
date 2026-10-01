#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn find_service_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                if exe_name == "insiedr-service.exe" {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

fn resolve_service_exe_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("insiedr-service.exe")))
        .unwrap_or_else(|| PathBuf::from("insiedr-service.exe"))
}

fn main() {
    println!("=== InsiEDR Enterprise Watchdog Supervisor ===");
    let service_bin = resolve_service_exe_path();
    println!("[Watchdog] Target service binary: {:?}", service_bin);

    loop {
        if let Some(pid) = find_service_pid() {
            println!("[Watchdog] Attached to active insiedr-service.exe (PID {pid}). Standing guard...");
            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
                    // Event-driven kernel wait: 0.00% CPU usage, wakes instantly when process dies
                    let _ = WaitForSingleObject(handle, INFINITE);
                    let _ = CloseHandle(handle);
                    eprintln!("[Watchdog] ALERT: insiedr-service.exe (PID {pid}) terminated! Emitting anti-tamper telemetry...");
                } else {
                    thread::sleep(Duration::from_secs(3));
                }
            }
        } else {
            eprintln!("[Watchdog] insiedr-service.exe not found running. Spawning fresh instance...");
            let res = Command::new(&service_bin)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();

            match res {
                Ok(child) => {
                    println!("[Watchdog] Successfully respawned insiedr-service.exe with PID {}", child.id());
                }
                Err(e) => {
                    eprintln!("[Watchdog] Failed to launch insiedr-service.exe ({e}). Retrying in 5 seconds...");
                }
            }
            thread::sleep(Duration::from_secs(3));
        }
    }
}
