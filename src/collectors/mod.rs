pub mod activity;
pub mod browser_history;
pub mod clipboard;
pub mod decoy;
pub mod dns;
pub mod driver_monitor;
pub mod email;
pub mod file_integrity;
pub mod keystroke_biometrics;
pub mod logon;
pub mod lsass;
pub mod memory_scanner;
pub mod named_pipe;
pub mod network;
pub mod persistence;
pub mod process_watcher;
pub mod semantics;
pub mod short_term_edr;
pub mod usb_devices;
pub mod usn;
pub mod wmi_activity;

use crate::protocol::payload::CollectorResult;

/// Trait implemented by all InsiEDR telemetry collectors
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    fn collect(&self) -> CollectorResult;

    /// Unclassified collectors remain unsuppressible until their semantics are reviewed.
    fn is_security_event_collector(&self) -> bool {
        semantics::is_security_event_collector(self.name())
    }

    /// Mixed collectors can contain newly drained events even when their metrics repeat.
    fn has_security_events(&self, result: &CollectorResult) -> bool {
        semantics::has_security_events(self.name(), result)
    }

    fn has_active_threat(&self, result: &CollectorResult) -> bool {
        semantics::has_active_threat(self.name(), result)
    }
}
