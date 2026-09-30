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
pub mod named_pipe;
pub mod network;
pub mod persistence;
pub mod process_watcher;
pub mod short_term_edr;
pub mod usb_devices;
pub mod usn;
pub mod wmi_activity;
pub mod memory_scanner;

use crate::protocol::payload::CollectorResult;

/// Trait implemented by all InsiEDR telemetry collectors
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    fn collect(&self) -> CollectorResult;
}
