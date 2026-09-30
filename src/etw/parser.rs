use std::collections::HashMap;
use chrono::Utc;
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_RECORD, TRACE_EVENT_INFO, PROPERTY_DATA_DESCRIPTOR,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};
use crate::etw::types::{EtwDnsQuery, EtwEvent, EtwImageLoad, EtwProcessStart, EtwProcessStop};

pub const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2ad6_0e1b_42e0_a572_18645b2a2626);
pub const DNS_CLIENT_GUID: GUID = GUID::from_u128(0x1c950233_bece_49a9_b6e4_9ae8d41c61f1);

#[derive(Debug, Clone)]
pub enum EtwPropertyValue {
    String(String),
    UInt32(u32),
    UInt64(u64),
    Int32(i32),
    Int64(i64),
    Bytes(Vec<u8>),
}

impl EtwPropertyValue {
    pub fn as_string(&self) -> String {
        match self {
            EtwPropertyValue::String(s) => s.clone(),
            EtwPropertyValue::UInt32(u) => u.to_string(),
            EtwPropertyValue::UInt64(u) => u.to_string(),
            EtwPropertyValue::Int32(i) => i.to_string(),
            EtwPropertyValue::Int64(i) => i.to_string(),
            EtwPropertyValue::Bytes(b) => format!("<{} bytes>", b.len()),
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            EtwPropertyValue::UInt32(u) => *u,
            EtwPropertyValue::Int32(i) => *i as u32,
            EtwPropertyValue::UInt64(u) => *u as u32,
            EtwPropertyValue::Int64(i) => *i as u32,
            EtwPropertyValue::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            EtwPropertyValue::UInt64(u) => *u,
            EtwPropertyValue::UInt32(u) => *u as u64,
            EtwPropertyValue::Int64(i) => *i as u64,
            EtwPropertyValue::Int32(i) => *i as u64,
            EtwPropertyValue::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        }
    }
}

pub fn parse_sid_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let sub_auth_count = bytes[1] as usize;
    if bytes.len() < 8 + sub_auth_count * 4 {
        return None;
    }
    let mut id_auth: u64 = 0;
    for &b in &bytes[2..8] {
        id_auth = (id_auth << 8) | (b as u64);
    }
    let mut sid_str = format!("S-{}-{}", revision, id_auth);
    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        let sub_auth = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        sid_str.push_str(&format!("-{}", sub_auth));
    }
    Some(sid_str)
}

pub unsafe fn parse_event_record(record: *const EVENT_RECORD) -> Option<EtwEvent> {
    if record.is_null() {
        return None;
    }
    let rec = &*record;
    let provider_id = rec.EventHeader.ProviderId;
    let event_id = rec.EventHeader.EventDescriptor.Id;

    if provider_id != KERNEL_PROCESS_GUID && provider_id != DNS_CLIENT_GUID {
        return None;
    }

    let mut buffer_size = 0u32;
    let _ = TdhGetEventInformation(record, None, None, &mut buffer_size);
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let p_info = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(record, None, Some(p_info), &mut buffer_size) != 0 {
        return None;
    }

    let info = &*p_info;
    let count = info.TopLevelPropertyCount;
    let props = std::slice::from_raw_parts(info.EventPropertyInfoArray.as_ptr(), count as usize);

    let mut map: HashMap<String, EtwPropertyValue> = HashMap::with_capacity(count as usize);

    for prop in props {
        if (prop.NameOffset as usize) >= buffer_size as usize {
            continue;
        }
        let name_ptr = (p_info as usize + prop.NameOffset as usize) as *const u16;
        let max_chars = (buffer_size as usize - prop.NameOffset as usize) / 2;
        let mut len = 0;
        while len < max_chars && *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name = String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, len));

        let pdd = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: name_ptr as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };

        let mut prop_size = 0u32;
        if TdhGetPropertySize(record, None, &[pdd], &mut prop_size) == 0 && prop_size > 0 {
            let mut val_buf = vec![0u8; prop_size as usize];
            if TdhGetProperty(record, None, &[pdd], &mut val_buf) == 0 {
                let in_type = prop.Anonymous1.nonStructType.InType;
                let parsed_val = match in_type {
                    1 => {
                        // TDH_INTYPE_UNICODESTRING (UTF-16) - Alignment-Safe chunks
                        let u16_vec: Vec<u16> = val_buf
                            .chunks_exact(2)
                            .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
                            .collect();
                        let s = String::from_utf16_lossy(&u16_vec)
                            .trim_end_matches('\0')
                            .to_string();
                        EtwPropertyValue::String(s)
                    }
                    2 => {
                        // TDH_INTYPE_ANSISTRING (ASCII/UTF-8)
                        let s = String::from_utf8_lossy(&val_buf)
                            .trim_end_matches('\0')
                            .to_string();
                        EtwPropertyValue::String(s)
                    }
                    7 => {
                        // TDH_INTYPE_INT32
                        if val_buf.len() >= 4 {
                            let val = i32::from_ne_bytes(val_buf[0..4].try_into().unwrap());
                            EtwPropertyValue::Int32(val)
                        } else {
                            EtwPropertyValue::Bytes(val_buf)
                        }
                    }
                    8 => {
                        // TDH_INTYPE_UINT32
                        if val_buf.len() >= 4 {
                            let val = u32::from_ne_bytes(val_buf[0..4].try_into().unwrap());
                            EtwPropertyValue::UInt32(val)
                        } else {
                            EtwPropertyValue::Bytes(val_buf)
                        }
                    }
                    9 => {
                        // TDH_INTYPE_INT64
                        if val_buf.len() >= 8 {
                            let val = i64::from_ne_bytes(val_buf[0..8].try_into().unwrap());
                            EtwPropertyValue::Int64(val)
                        } else {
                            EtwPropertyValue::Bytes(val_buf)
                        }
                    }
                    10 => {
                        // TDH_INTYPE_UINT64
                        if val_buf.len() >= 8 {
                            let val = u64::from_ne_bytes(val_buf[0..8].try_into().unwrap());
                            EtwPropertyValue::UInt64(val)
                        } else {
                            EtwPropertyValue::Bytes(val_buf)
                        }
                    }
                    19 => {
                        // TDH_INTYPE_SID - Binary Windows SID parser
                        if let Some(sid) = parse_sid_bytes(&val_buf) {
                            EtwPropertyValue::String(sid)
                        } else {
                            EtwPropertyValue::Bytes(val_buf)
                        }
                    }
                    _ => EtwPropertyValue::Bytes(val_buf),
                };
                map.insert(name, parsed_val);
            }
        }
    }

    let timestamp = Utc::now();

    // Map according to Provider and Event ID
    if provider_id == KERNEL_PROCESS_GUID {
        match event_id {
            1 => {
                // Process Start
                let pid = map.get("ProcessID")
                    .or_else(|| map.get("ProcessId"))
                    .map(|v| v.as_u32())
                    .unwrap_or(rec.EventHeader.ProcessId);
                let parent_pid = map.get("ParentProcessID")
                    .or_else(|| map.get("ParentProcessId"))
                    .map(|v| v.as_u32())
                    .unwrap_or(0);
                let image_name = map.get("ImageFileName")
                    .or_else(|| map.get("ImageName"))
                    .map(|v| v.as_string())
                    .unwrap_or_default();
                let command_line = map.get("CommandLine")
                    .map(|v| v.as_string())
                    .unwrap_or_default();
                let user_sid = map.get("UserSID")
                    .or_else(|| map.get("UserSid"))
                    .map(|v| v.as_string());

                Some(EtwEvent::ProcessStart(EtwProcessStart {
                    pid,
                    parent_pid,
                    image_name,
                    command_line,
                    user_sid,
                    timestamp,
                }))
            }
            2 => {
                // Process Stop
                let pid = map.get("ProcessID")
                    .or_else(|| map.get("ProcessId"))
                    .map(|v| v.as_u32())
                    .unwrap_or(rec.EventHeader.ProcessId);
                let exit_code = map.get("ExitCode")
                    .map(|v| v.as_u32())
                    .unwrap_or(0);

                Some(EtwEvent::ProcessStop(EtwProcessStop {
                    pid,
                    exit_code,
                    timestamp,
                }))
            }
            5 => {
                // Image Load
                let pid = map.get("ProcessID")
                    .or_else(|| map.get("ProcessId"))
                    .map(|v| v.as_u32())
                    .unwrap_or(rec.EventHeader.ProcessId);
                let file_name = map.get("FileName")
                    .or_else(|| map.get("ImageName"))
                    .map(|v| v.as_string())
                    .unwrap_or_default();
                let image_base = map.get("ImageBase")
                    .map(|v| v.as_u64())
                    .unwrap_or(0);
                let image_size = map.get("ImageSize")
                    .map(|v| v.as_u64())
                    .unwrap_or(0);

                Some(EtwEvent::ImageLoad(EtwImageLoad {
                    pid,
                    file_name,
                    image_base,
                    image_size,
                    timestamp,
                }))
            }
            _ => None,
        }
    } else if provider_id == DNS_CLIENT_GUID {
        // DNS Client Events
        let pid = rec.EventHeader.ProcessId;
        let query_name = map.get("QueryName")
            .map(|v| v.as_string())
            .unwrap_or_default();
        let query_type = map.get("QueryType")
            .map(|v| v.as_u32())
            .unwrap_or(0);
        let query_results = map.get("QueryResults")
            .map(|v| v.as_string())
            .unwrap_or_default();
        let status = map.get("Status")
            .map(|v| v.as_u32())
            .unwrap_or(0);

        if !query_name.is_empty() {
            Some(EtwEvent::DnsQuery(EtwDnsQuery {
                pid,
                query_name,
                query_type,
                query_results,
                status,
                timestamp,
            }))
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_sid_decoding() {
        // S-1-5-18 (NT AUTHORITY\SYSTEM)
        let system_sid_bytes = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(parse_sid_bytes(&system_sid_bytes), Some("S-1-5-18".to_string()));

        // S-1-5-32-544 (BUILTIN\Administrators)
        let admin_sid_bytes = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0x00, 0x00];
        assert_eq!(parse_sid_bytes(&admin_sid_bytes), Some("S-1-5-32-544".to_string()));

        // Corrupted / too short
        assert_eq!(parse_sid_bytes(&[1, 1, 0, 0]), None);
    }
}

