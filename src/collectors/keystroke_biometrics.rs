use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;
use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, SetWindowsHookExW,
    HHOOK, KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL,
    WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

// VK_BACK = 0x08
const VK_BACK_CODE: u32 = 0x08;

// ─── Shared State ────────────────────────────────────────────────────────────

#[derive(Default)]
struct KeystrokeState {
    dwell_times_ms:  Vec<f64>,
    flight_times_ms: Vec<f64>,
    backspace_count: u32,
    total_keys:      u32,
    /// Per-key press instant keyed by vk_code
    key_down_at:     HashMap<u32, Instant>,
    /// Instant when most recent key was released
    last_key_up_at:  Option<Instant>,
}

static KEYSTROKE_STATE: OnceLock<Arc<Mutex<KeystrokeState>>> = OnceLock::new();

fn get_or_init_state() -> &'static Arc<Mutex<KeystrokeState>> {
    KEYSTROKE_STATE.get_or_init(|| {
        let state = Arc::new(Mutex::new(KeystrokeState::default()));
        let state_for_thread = Arc::clone(&state);

        thread::Builder::new()
            .name("insiedr-keystroke-hook".into())
            .spawn(move || {
                // Store the arc in global so the hook callback can reach it
                let _ = KEYSTROKE_STATE.set(state_for_thread);

                unsafe {
                    let _hook: HHOOK = SetWindowsHookExW(
                        WH_KEYBOARD_LL,
                        Some(keyboard_hook_proc),
                        None,  // hmod = NULL works for low-level (global) hooks
                        0,     // dwThreadId = 0 → system-wide
                    )
                    .expect("[KeystrokeHook] SetWindowsHookExW failed — running without keyboard telemetry");

                    // Message pump — the hook only fires when this thread pumps messages
                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, None, 0, 0).as_bool() {}
                }
            })
            .expect("[KeystrokeHook] Failed to spawn hook thread");

        state
    })
}

/// Low-level keyboard hook callback — runs on the hook thread only.
unsafe extern "system" fn keyboard_hook_proc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 {
        let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        let vk = kb.vkCode;

        if let Some(arc) = KEYSTROKE_STATE.get() {
            if let Ok(mut s) = arc.try_lock() {
                let msg = wparam.0 as u32;

                if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
                    let now = Instant::now();

                    // Flight time = gap from last key-up to this key-down
                    if let Some(up_at) = s.last_key_up_at {
                        if let Some(flight_ms) = now.checked_duration_since(up_at)
                            .map(|d| d.as_secs_f64() * 1000.0)
                        {
                            // Human inter-key gap: 0–2000 ms
                            if (0.0..2_000.0).contains(&flight_ms) {
                                s.flight_times_ms.push(flight_ms);
                            }
                        }
                    }

                    s.key_down_at.insert(vk, now);
                    s.total_keys += 1;
                    if vk == VK_BACK_CODE { s.backspace_count += 1; }

                } else if msg == WM_KEYUP || msg == WM_SYSKEYUP {
                    let now = Instant::now();

                    // Dwell time = how long key was held
                    if let Some(down_at) = s.key_down_at.remove(&vk) {
                        if let Some(dwell_ms) = now.checked_duration_since(down_at)
                            .map(|d| d.as_secs_f64() * 1000.0)
                        {
                            // Human key-hold duration: 1–500 ms
                            if (1.0..500.0).contains(&dwell_ms) {
                                s.dwell_times_ms.push(dwell_ms);
                            }
                        }
                    }
                    s.last_key_up_at = Some(now);
                }

                // Rolling window — keep ≤ 1000 samples each
                if s.dwell_times_ms.len() > 1_000 { s.dwell_times_ms.drain(..500); }
                if s.flight_times_ms.len() > 1_000 { s.flight_times_ms.drain(..500); }
            }
        }
    }

    CallNextHookEx(HHOOK::default(), code, wparam, lparam)
}

// ─── Stats helpers ───────────────────────────────────────────────────────────

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 }
}

fn std_dev(v: &[f64]) -> f64 {
    if v.len() < 2 { return 0.0; }
    let m = mean(v);
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
}

fn chars_per_minute(mean_flight_ms: f64) -> f64 {
    if mean_flight_ms <= 0.0 { 0.0 } else { 60_000.0 / mean_flight_ms }
}

// ─── Collector ───────────────────────────────────────────────────────────────

pub struct KeystrokeBiometricsCollector;

impl KeystrokeBiometricsCollector {
    pub fn new() -> Self {
        get_or_init_state(); // eagerly start the hook thread
        Self
    }
}

impl Default for KeystrokeBiometricsCollector {
    fn default() -> Self { Self::new() }
}

impl Collector for KeystrokeBiometricsCollector {
    fn name(&self) -> &'static str { "keystroke-collector" }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let arc = get_or_init_state();

        let (dwell, flight, backspace_count, total_keys) = {
            let s = arc.lock().expect("keystroke mutex poisoned");
            (s.dwell_times_ms.clone(), s.flight_times_ms.clone(), s.backspace_count, s.total_keys)
        };

        let mean_dwell  = mean(&dwell);
        let std_dwell   = std_dev(&dwell);
        let mean_flight = mean(&flight);
        let std_flight  = std_dev(&flight);
        let cpm         = chars_per_minute(mean_flight);
        let backspace_ratio = if total_keys > 0 {
            backspace_count as f64 / total_keys as f64
        } else { 0.0 };

        // Up to 20 recent [dwell_ms, flight_ms] pairs for downstream ML
        let pairs: Vec<[f64; 2]> = dwell.iter()
            .zip(flight.iter())
            .rev()
            .take(20)
            .map(|(&d, &f)| [
                (d * 100.0).round() / 100.0,
                (f * 100.0).round() / 100.0,
            ])
            .collect();

        let quality = if total_keys >= 10 {
            QualityFlags { exact: true, partial: false, elevated: false, heuristic: false }
        } else {
            QualityFlags { exact: false, partial: true, elevated: false, heuristic: true }
        };

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "keystroke_timings":    pairs,
                "mean_dwell_time_ms":   (mean_dwell  * 100.0).round() / 100.0,
                "std_dwell_time_ms":    (std_dwell   * 100.0).round() / 100.0,
                "mean_flight_time_ms":  (mean_flight * 100.0).round() / 100.0,
                "std_flight_time_ms":   (std_flight  * 100.0).round() / 100.0,
                "typing_speed_cpm":     (cpm         *  10.0).round() /  10.0,
                "backspace_ratio":      (backspace_ratio * 1000.0).round() / 1000.0,
                "total_keys_sampled":   total_keys,
                "dwell_sample_count":   dwell.len(),
                "flight_sample_count":  flight.len()
            }),
            quality,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mean_and_stddev() {
        let v = vec![10.0, 20.0, 30.0];
        assert!((mean(&v) - 20.0).abs() < 0.001);
        assert!(std_dev(&v) > 0.0);
    }

    #[test]
    fn test_keystroke_collector_runs() {
        let collector = KeystrokeBiometricsCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "keystroke-collector");
        assert!(res.success);
        assert!(res.metrics.get("mean_dwell_time_ms").is_some());
        // No key presses in test — total_keys = 0 is valid
        println!("Total keys sampled: {:?}", res.metrics.get("total_keys_sampled"));
    }
}
