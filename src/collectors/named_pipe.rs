use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW};

pub struct NamedPipeCollector;

impl NamedPipeCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for NamedPipeCollector {
    fn name(&self) -> &'static str {
        "named-pipe-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let search_path = windows::core::w!(r"\\.\pipe\*");
        let mut find_data = WIN32_FIND_DATAW::default();
        let mut pipes = Vec::new();

        unsafe {
            let handle = FindFirstFileW(search_path, &mut find_data);
            if let Ok(h) = handle {
                if h != INVALID_HANDLE_VALUE {
                    loop {
                        let len = find_data
                            .cFileName
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(find_data.cFileName.len());
                        let pipe_name = String::from_utf16_lossy(&find_data.cFileName[..len]);
                        if !pipe_name.is_empty() {
                            pipes.push(pipe_name);
                        }
                        if FindNextFileW(h, &mut find_data).is_err() {
                            break;
                        }
                    }
                    let _ = FindClose(h);
                }
            }
        }

        let total = pipes.len();
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "pipe_count": total,
                "named_pipes_sample": pipes.iter().take(50).collect::<Vec<_>>()
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
    fn test_named_pipe_collector_runs() {
        let collector = NamedPipeCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "named-pipe-monitor");
        assert!(res.success);
        assert!(res.metrics.get("pipe_count").is_some());
    }
}
