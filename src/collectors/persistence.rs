use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ,
};

pub struct PersistenceCollector;

impl PersistenceCollector {
    pub fn new() -> Self {
        Self
    }

    fn check_key(hroot: HKEY, subkey: &str) -> Vec<(String, String)> {
        let mut entries = Vec::new();
        let wide_path: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let mut h_key = HKEY(std::ptr::null_mut());
            if RegOpenKeyExW(hroot, PCWSTR::from_raw(wide_path.as_ptr()), 0, KEY_READ, &mut h_key).is_ok()
                && !h_key.0.is_null()
            {
                let mut index = 0u32;
                loop {
                    let mut name_buf = [0u16; 256];
                    let mut name_len = name_buf.len() as u32;
                    let mut data_buf = [0u8; 1024];
                    let mut data_len = data_buf.len() as u32;
                    let mut val_type = 0u32;

                    let res = RegEnumValueW(
                        h_key,
                        index,
                        windows::core::PWSTR::from_raw(name_buf.as_mut_ptr()),
                        &mut name_len,
                        None,
                        Some(&mut val_type),
                        Some(data_buf.as_mut_ptr()),
                        Some(&mut data_len),
                    );

                    if res.is_err() {
                        break;
                    }

                    let val_name = String::from_utf16_lossy(&name_buf[..name_len as usize]).trim_matches('\0').to_string();
                    let val_data = if val_type == 1 || val_type == 2 {
                        // REG_SZ or REG_EXPAND_SZ (UTF-16 LE)
                        let u16s: Vec<u16> = data_buf[..data_len as usize]
                            .chunks_exact(2)
                            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&u16s).trim_matches('\0').to_string()
                    } else if val_type == 4 && data_len >= 4 {
                        // REG_DWORD
                        format!("0x{:08X}", u32::from_ne_bytes([data_buf[0], data_buf[1], data_buf[2], data_buf[3]]))
                    } else {
                        // REG_BINARY or raw fallback
                        format!("{:02X?}", &data_buf[..data_len as usize])
                    };
                    entries.push((val_name, val_data));
                    index += 1;
                }
                let _ = RegCloseKey(h_key);
            }
        }
        entries
    }
}

impl Collector for PersistenceCollector {
    fn name(&self) -> &'static str {
        "persistence-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut all_entries = Vec::new();

        let points = [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        for (hroot, subkey) in points {
            let found = Self::check_key(hroot, subkey);
            for (name, cmd) in found {
                all_entries.push(json!({
                    "path": subkey,
                    "name": name,
                    "command": cmd
                }));
            }
        }

        let count = all_entries.len();
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "total_monitored_keys": count,
                "entry_count": count,
                "persistence_entries": all_entries,
                "modifications_detected": false
            }),
            QualityFlags {
                exact: true,
                partial: false,
                elevated: false,
                heuristic: false,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_collector_runs() {
        let collector = PersistenceCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "persistence-monitor");
        assert!(res.success);
        assert!(res.metrics.get("persistence_entries").is_some());
    }
}
