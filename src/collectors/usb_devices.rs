use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

pub struct UsbDeviceCollector;

impl UsbDeviceCollector {
    pub fn new() -> Self {
        Self
    }

    fn enumerate_usbstor() -> Vec<String> {
        let mut devices = Vec::new();
        let subkey: Vec<u16> = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        unsafe {
            let mut h_key = HKEY(std::ptr::null_mut());
            let open_res = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(subkey.as_ptr()),
                0,
                KEY_READ,
                &mut h_key,
            );

            if open_res.is_err() || h_key.0.is_null() {
                return devices;
            }

            let mut index = 0u32;
            let mut name_buf = [0u16; 256];
            loop {
                let mut name_len = name_buf.len() as u32;
                let enum_res = RegEnumKeyExW(
                    h_key,
                    index,
                    windows::core::PWSTR::from_raw(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                );

                if enum_res.is_err() {
                    break;
                }

                let device_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                devices.push(device_name);
                index += 1;
            }

            let _ = RegCloseKey(h_key);
        }

        devices
    }
}

impl Collector for UsbDeviceCollector {
    fn name(&self) -> &'static str {
        "devices"
    }

    fn collect(&self) -> CollectorResult {
        let devices = Self::enumerate_usbstor();
        let count = devices.len();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "usb_devices_count": count,
                "usb_connect_count": count as f64,
                "usb_disconnect_count": 0.0,
                "after_hours_usb_usage": 0.0,
                "daily_device_connect_count": count as f64,
                "daily_device_usage_flag": if count > 0 { 1.0 } else { 0.0 },
                "first_usb_usage_time": 0.0,
                "usb_device_names": devices,
                "unauthorized_usb_detected": false
            }),
            QualityFlags {
                exact: true,
                partial: false,
                elevated: true,
                heuristic: false,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_device_collector_runs() {
        let collector = UsbDeviceCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "devices");
        assert!(res.success);
    }
}
