use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, BOOL, ERROR_MORE_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const IPC_PIPE_NAME: &str = r"\\.\pipe\InsiEDR-Telemetry-IPC";

/// Server side of Named Pipe (Runs in Session 0 Windows Service)
pub struct NamedPipeServer {
    pipe_handle: HANDLE,
}

impl NamedPipeServer {
    pub fn create(pipe_name: &str) -> Result<Self, String> {
        let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            // DACL: Allow Everyone read/write, Administrators/SYSTEM full access
            let mut p_sd = PSECURITY_DESCRIPTOR::default();
            let sddl = windows::core::w!("D:(A;;GRGW;;;WD)(A;;GA;;;BA)(A;;GA;;;SY)");
            let has_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SDDL_REVISION_1,
                &mut p_sd,
                None,
            ).is_ok();

            let sa = if has_sd {
                Some(SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: p_sd.0,
                    bInheritHandle: BOOL(0),
                })
            } else {
                None
            };

            let handle = CreateNamedPipeW(
                PCWSTR::from_raw(wide_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                5000,
                sa.as_ref().map(|s| s as *const SECURITY_ATTRIBUTES),
            );

            if !p_sd.0.is_null() {
                let _ = LocalFree(HLOCAL(p_sd.0));
            }

            if handle == INVALID_HANDLE_VALUE {
                return Err("Failed to create Named Pipe".into());
            }

            Ok(Self { pipe_handle: handle })
        }
    }

    pub fn wait_for_client(&self) -> bool {
        unsafe {
            let res = ConnectNamedPipe(self.pipe_handle, None);
            if res.is_ok() {
                return true;
            }
            // If client connected in the interval between CreateNamedPipe and ConnectNamedPipe,
            // ConnectNamedPipe returns ERROR_PIPE_CONNECTED. This is an active connection.
            if let Err(ref e) = res {
                if e.code() == ERROR_PIPE_CONNECTED.to_hresult() {
                    return true;
                }
            }
            false
        }
    }

    pub fn read_message(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let mut message = Vec::new();
            let mut chunk = vec![0u8; 65536];

            loop {
                let mut bytes_read = 0u32;
                let res = ReadFile(
                    self.pipe_handle,
                    Some(&mut chunk),
                    Some(&mut bytes_read),
                    None,
                );

                if bytes_read > 0 {
                    message.extend_from_slice(&chunk[..bytes_read as usize]);
                }

                if res.is_ok() {
                    // Complete message received
                    break;
                }

                // If ERROR_MORE_DATA, the message spans across multiple chunks
                if let Err(ref e) = res {
                    if e.code() == ERROR_MORE_DATA.to_hresult() {
                        continue;
                    }
                }

                if message.is_empty() {
                    return Err("Failed to read from named pipe".into());
                } else {
                    break;
                }
            }

            Ok(message)
        }
    }

    pub fn disconnect(&self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe_handle);
        }
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.pipe_handle);
        }
    }
}

/// Client side of Named Pipe (Runs in Session 1+ User Broker)
pub struct NamedPipeClient {
    handle: HANDLE,
}

impl NamedPipeClient {
    pub fn connect(pipe_name: &str) -> Result<Self, String> {
        let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            for attempt in 0..3 {
                let handle = CreateFileW(
                    PCWSTR::from_raw(wide_name.as_ptr()),
                    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    HANDLE(ptr::null_mut()),
                );

                match handle {
                    Ok(h) if h != INVALID_HANDLE_VALUE => return Ok(Self { handle: h }),
                    Err(e) if e.code() == ERROR_PIPE_BUSY.to_hresult() && attempt < 2 => {
                        let _ = WaitNamedPipeW(PCWSTR::from_raw(wide_name.as_ptr()), 2000);
                        continue;
                    }
                    Err(e) => {
                        if attempt == 2 {
                            return Err(format!("Failed to connect to Named Pipe: {e}"));
                        }
                    }
                    _ => {}
                }
            }
            Err("Named Pipe connection timed out".into())
        }
    }

    pub fn send_message(&self, data: &[u8]) -> Result<(), String> {
        unsafe {
            let mut bytes_written = 0u32;
            WriteFile(
                self.handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|e| format!("Failed to write to named pipe: {e}"))?;

            Ok(())
        }
    }
}

impl Drop for NamedPipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

unsafe impl Send for NamedPipeServer {}
unsafe impl Sync for NamedPipeServer {}
unsafe impl Send for NamedPipeClient {}
unsafe impl Sync for NamedPipeClient {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_pipe_creation_with_sddl() {
        let test_pipe_name = format!(r"\\.\pipe\InsiEDR-Test-Pipe-{}", uuid::Uuid::new_v4());
        let server = NamedPipeServer::create(&test_pipe_name);
        assert!(server.is_ok(), "NamedPipeServer should be successfully created with SDDL");
    }
}
