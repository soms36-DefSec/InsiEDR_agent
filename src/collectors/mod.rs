pub mod activity;
pub mod file_integrity;
pub mod keystroke_biometrics;
pub mod logon;
pub mod network;
pub mod process_watcher;
pub mod short_term_edr;
pub mod usb_devices;

use crate::protocol::payload::CollectorResult;

/// Trait implemented by all InsiEDR telemetry collectors
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    fn collect(&self) -> CollectorResult;
}
