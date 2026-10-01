use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::net::Ipv4Addr;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};

pub struct NetworkCollector;

impl NetworkCollector {
    pub fn new() -> Self {
        Self
    }

    fn query_tcp_sockets() -> Vec<serde_json::Value> {
        let mut connections = Vec::new();
        unsafe {
            let mut size: u32 = 0;
            // First call to determine buffer size
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                true,
                2, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size == 0 {
                return connections;
            }

            // Retry loop to handle concurrent socket creations between size calculation and query
            let mut buffer = vec![0u8; (size as usize) + 4096];
            let mut ret = 1;
            for _ in 0..4 {
                ret = GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    true,
                    2, // AF_INET
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if ret == 0 {
                    break;
                }
                buffer.resize((size as usize) + 4096, 0);
            }

            if ret == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;
                let rows_ptr = table.table.as_ptr();

                for i in 0..num_entries.min(100) {
                    let row = &*rows_ptr.add(i);
                    let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                    let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                    let local_port = u16::from_be(row.dwLocalPort as u16);
                    let remote_port = u16::from_be(row.dwRemotePort as u16);
                    let pid = row.dwOwningPid;

                    connections.push(json!({
                        "local_addr": format!("{}:{}", local_ip, local_port),
                        "remote_addr": format!("{}:{}", remote_ip, remote_port),
                        "pid": pid,
                        "state": row.dwState
                    }));
                }
            }
        }
        connections
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&self) -> CollectorResult {
        let connections = Self::query_tcp_sockets();
        let count = connections.len();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "active_connections_count": count,
                "connections_sample": connections
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
    fn test_network_collector_runs() {
        let collector = NetworkCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "network");
        assert!(res.success);
        assert!(res.metrics.get("active_connections_count").is_some());
    }
}
