use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;

static LAST_SEQ: AtomicU32 = AtomicU32::new(0);

pub struct ClipboardCollector;

impl ClipboardCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClipboardCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ClipboardCollector {
    fn name(&self) -> &'static str {
        "clipboard-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let current_seq = unsafe { GetClipboardSequenceNumber() };
        let prev_seq = LAST_SEQ.swap(current_seq, Ordering::SeqCst);

        let delta = if prev_seq == 0 {
            0
        } else {
            current_seq.saturating_sub(prev_seq)
        };

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "clipboard_sequence": current_seq,
                "clipboard_copy_count": delta,
                "monitor_active": true
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
    fn test_clipboard_collector_runs() {
        let collector = ClipboardCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "clipboard-monitor");
        assert!(res.success);
    }
}
