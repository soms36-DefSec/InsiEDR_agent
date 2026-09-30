use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use log::{debug, info, warn};
use tokio::sync::broadcast;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    WNODE_FLAG_TRACED_GUID,
};

use crate::etw::parser::{parse_event_record, DNS_CLIENT_GUID, KERNEL_PROCESS_GUID};
use crate::etw::types::EtwEvent;

const SESSION_NAME_W: PCWSTR = windows::core::w!("InsiEDR-Kernel-Trace");

pub struct EtwSession {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    is_running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
    event_tx: broadcast::Sender<EtwEvent>,
}

unsafe impl Send for EtwSession {}
unsafe impl Sync for EtwSession {}

impl EtwSession {
    pub fn start() -> Result<Self, String> {
        let (tx, _) = broadcast::channel(1024);

        // 1. Prepare EVENT_TRACE_PROPERTIES buffer
        // Size must accommodate properties + 2 * MAX_PATH * sizeof(u16)
        let buffer_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * (260 * std::mem::size_of::<u16>());
        let mut prop_buffer = vec![0u8; buffer_size];
        let p_props = prop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            (*p_props).Wnode.BufferSize = buffer_size as u32;
            (*p_props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*p_props).Wnode.ClientContext = 1; // QPC timestamp
            (*p_props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*p_props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*p_props).LogFileNameOffset = 0;
        }

        let mut session_handle = CONTROLTRACE_HANDLE::default();

        // Try starting trace session
        let mut status = unsafe {
            StartTraceW(&mut session_handle, SESSION_NAME_W, p_props)
        };

        // If session already exists from previous crash, stop it first and retry
        if status == ERROR_ALREADY_EXISTS {
            info!("Existing ETW trace session found; stopping prior session...");
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    SESSION_NAME_W,
                    p_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            // Re-initialize buffer
            unsafe {
                (*p_props).Wnode.BufferSize = buffer_size as u32;
                (*p_props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                (*p_props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                (*p_props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            }
            status = unsafe {
                StartTraceW(&mut session_handle, SESSION_NAME_W, p_props)
            };
        }

        if status.0 != 0 {
            return Err(format!("StartTraceW failed with Win32 error code: {:?}", status));
        }

        info!("ETW Kernel Session started successfully (Handle: {:?})", session_handle);

        // 2. Enable Providers: Kernel-Process & DNS-Client
        unsafe {
            // Kernel-Process Provider
            let k_res = EnableTraceEx2(
                session_handle,
                &KERNEL_PROCESS_GUID,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                4, // TRACE_LEVEL_INFORMATION
                0, // MatchAnyKeyword
                0, // MatchAllKeyword
                0,
                None,
            );
            if k_res.0 != 0 {
                warn!("EnableTraceEx2 for Kernel-Process returned: {:?}", k_res);
            } else {
                info!("Enabled Microsoft-Windows-Kernel-Process ETW provider");
            }

            // DNS-Client Provider
            let d_res = EnableTraceEx2(
                session_handle,
                &DNS_CLIENT_GUID,
                1,
                4,
                0,
                0,
                0,
                None,
            );
            if d_res.0 != 0 {
                warn!("EnableTraceEx2 for DNS-Client returned: {:?}", d_res);
            } else {
                info!("Enabled Microsoft-Windows-DNS-Client ETW provider");
            }
        }

        // 3. Prepare OpenTraceW
        let tx_box = Box::new(tx.clone());
        let tx_raw = Box::into_raw(tx_box);

        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = windows::core::PWSTR(SESSION_NAME_W.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);
        logfile.Context = tx_raw as *mut core::ffi::c_void;

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == 0 || trace_handle.Value == !0 {
            // Cleanup on failure
            unsafe {
                let _ = ControlTraceW(
                    session_handle,
                    SESSION_NAME_W,
                    p_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                let _ = Box::from_raw(tx_raw);
            }
            return Err("OpenTraceW returned invalid trace handle".to_string());
        }

        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();

        let tx_raw_addr = tx_raw as usize;

        // 4. Spawn background pump thread
        let worker_handle = std::thread::Builder::new()
            .name("insiedr-etw-pump".to_string())
            .spawn(move || {
                debug!("ETW ProcessTrace pump thread started");
                let mut handles = [trace_handle];
                let p_res = unsafe { ProcessTrace(&mut handles, None, None) };
                debug!("ETW ProcessTrace pump thread terminated with status: {:?}", p_res);
                is_running_clone.store(false, Ordering::SeqCst);
                // Free the Boxed sender when trace loop exits
                unsafe {
                    let _ = Box::from_raw(tx_raw_addr as *mut broadcast::Sender<EtwEvent>);
                }
            })
            .map_err(|e| format!("Failed to spawn ETW pump thread: {}", e))?;

        Ok(Self {
            session_handle,
            trace_handle,
            is_running,
            worker_handle: Some(worker_handle),
            event_tx: tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EtwEvent> {
        self.event_tx.subscribe()
    }

    pub fn is_active(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn stop(&mut self) {
        if !self.is_running.swap(false, Ordering::SeqCst) {
            return;
        }

        let buffer_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * (260 * std::mem::size_of::<u16>());
        let mut prop_buffer = vec![0u8; buffer_size];
        let p_props = prop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            (*p_props).Wnode.BufferSize = buffer_size as u32;
            (*p_props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            let _ = ControlTraceW(
                self.session_handle,
                SESSION_NAME_W,
                p_props,
                EVENT_TRACE_CONTROL_STOP,
            );
            let _ = CloseTrace(self.trace_handle);
        }

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }

        info!("ETW Kernel Session stopped cleanly");
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if rec.UserContext.is_null() {
        return;
    }

    let tx = &*(rec.UserContext as *const broadcast::Sender<EtwEvent>);

    if let Some(event) = parse_event_record(record) {
        let _ = tx.send(event);
    }
}
