//! ACK-driven collector state. Pending manifests travel with the durable spool record.
use crate::collectors::semantics::comparison_metrics;
use crate::protocol::payload::CollectorResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_SNAPSHOT_INTERVAL_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingState {
    session_id: String,
    generation: u64,
    observed_elapsed_ms: u64,
    pub full_snapshot: bool,
    fingerprints: HashMap<String, [u8; 32]>,
}

pub struct TelemetryStateCache {
    entries: HashMap<String, (u64, [u8; 32])>,
    session_id: String,
    generation: u64,
    origin: Instant,
    last_snapshot: Option<(u64, Instant)>,
    snapshot_interval: Duration,
}

impl TelemetryStateCache {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            session_id: uuid::Uuid::new_v4().to_string(),
            generation: 0,
            origin: Instant::now(),
            last_snapshot: None,
            snapshot_interval: Duration::from_secs(interval_secs.max(1)),
        }
    }

    pub fn snapshot_due(&self, now: Instant) -> bool {
        self.last_snapshot
            .map(|(_, observed)| now.saturating_duration_since(observed) >= self.snapshot_interval)
            .unwrap_or(true)
    }

    pub fn begin_batch(&mut self, now: Instant) -> PendingState {
        self.generation += 1;
        PendingState {
            session_id: self.session_id.clone(),
            generation: self.generation,
            observed_elapsed_ms: now.saturating_duration_since(self.origin).as_millis() as u64,
            full_snapshot: self.snapshot_due(now),
            fingerprints: HashMap::new(),
        }
    }

    /// Include health/quality transitions as well as metrics; ignore observation time only.
    /// JSON maps have deterministic ordering. Arrays retain their original semantics/order.
    pub fn stage_result(
        &self,
        pending: &mut PendingState,
        result: &CollectorResult,
        bypass_suppression: bool,
    ) -> Result<bool, serde_json::Error> {
        let comparison = serde_json::json!({
            "metrics": comparison_metrics(result),
            "hostname": result.hostname,
            "status": result.status,
            "success": result.success,
            "error": result.error,
            "quality": result.quality,
        });
        let fingerprint: [u8; 32] = Sha256::digest(serde_json::to_vec(&comparison)?).into();
        let changed = self.entries.get(&result.name).map(|(_, prior)| *prior != fingerprint).unwrap_or(true);
        let emit = pending.full_snapshot || bypass_suppression || changed;
        if emit {
            pending.fingerprints.insert(result.name.clone(), fingerprint);
        }
        Ok(emit)
    }

    /// A single acknowledged envelope commits all its staged state. Old spool records from
    /// another process lifetime never seed this process's baseline, and out-of-order ACKs
    /// cannot roll a collector's state backwards.
    pub fn commit_transmission(&mut self, pending: PendingState) {
        if pending.session_id != self.session_id {
            return;
        }
        for (name, fingerprint) in pending.fingerprints {
            if self.entries.get(&name).map(|(generation, _)| *generation > pending.generation).unwrap_or(false) {
                continue;
            }
            self.entries.insert(name, (pending.generation, fingerprint));
        }
        if pending.full_snapshot
            && self.last_snapshot.map(|(generation, _)| generation <= pending.generation).unwrap_or(true)
        {
            // Use collection time, not delayed delivery time, for the next full snapshot.
            self.last_snapshot = self.origin.checked_add(Duration::from_millis(pending.observed_elapsed_ms))
                .map(|observed| (pending.generation, observed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::payload::QualityFlags;
    use serde_json::json;

    fn result(value: serde_json::Value) -> CollectorResult {
        CollectorResult::success("network", "2026-10-01T00:00:00Z", value, QualityFlags::default())
    }

    #[test]
    fn first_run_unacked_retry_and_identical_acknowledged_state() {
        let mut cache = TelemetryStateCache::new(300);
        let r = result(json!({"count": 0, "alert": false, "sample": []}));
        let mut pending = cache.begin_batch(cache.origin);
        assert!(cache.stage_result(&mut pending, &r, false).unwrap());
        let mut retry = cache.begin_batch(cache.origin);
        assert!(cache.stage_result(&mut retry, &r, false).unwrap());
        cache.commit_transmission(pending);
        let mut next = cache.begin_batch(cache.origin);
        assert!(!cache.stage_result(&mut next, &r, false).unwrap());
        assert_eq!(r.metrics["count"], 0);
        assert_eq!(r.metrics["alert"], false);
    }

    #[test]
    fn changed_metrics_quality_errors_and_repeated_events_emit() {
        let mut cache = TelemetryStateCache::new(300);
        let mut r = result(json!({"count": 0}));
        let mut baseline = cache.begin_batch(cache.origin);
        cache.stage_result(&mut baseline, &r, false).unwrap();
        cache.commit_transmission(baseline);
        let mut next = cache.begin_batch(cache.origin);
        r.collected_at = "later".into();
        assert!(!cache.stage_result(&mut next, &r, false).unwrap());
        assert!(cache.stage_result(&mut next, &r, true).unwrap());
        r.quality.partial = true;
        assert!(cache.stage_result(&mut next, &r, false).unwrap());
        r.quality.partial = false;
        r.metrics["count"] = json!(1);
        assert!(cache.stage_result(&mut next, &r, false).unwrap());
        r.metrics["count"] = json!(0);
        r.status = "failed".into();
        assert!(cache.stage_result(&mut next, &r, false).unwrap());
    }

    #[test]
    fn global_snapshot_deadline_is_not_postponed_by_deltas_or_late_ack() {
        let mut cache = TelemetryStateCache::new(300);
        let start = cache.origin;
        let mut full = cache.begin_batch(start);
        cache.stage_result(&mut full, &result(json!({"count": 0})), false).unwrap();
        cache.commit_transmission(full);
        let mut delta = cache.begin_batch(start + Duration::from_secs(290));
        assert!(!delta.full_snapshot);
        cache.stage_result(&mut delta, &result(json!({"count": 1})), false).unwrap();
        cache.commit_transmission(delta);
        assert!(!cache.snapshot_due(start + Duration::from_secs(299)));
        assert!(cache.snapshot_due(start + Duration::from_secs(300)));
    }

    #[test]
    fn spool_roundtrip_and_out_of_order_ack_cannot_regress_state() {
        let mut cache = TelemetryStateCache::new(300);
        let start = cache.origin;
        let mut old = cache.begin_batch(start);
        cache.stage_result(&mut old, &result(json!({"count": 0})), false).unwrap();
        let mut new = cache.begin_batch(start);
        cache.stage_result(&mut new, &result(json!({"count": 1})), false).unwrap();
        let serialized = serde_json::to_string(&new).unwrap();
        cache.commit_transmission(serde_json::from_str(&serialized).unwrap());
        cache.commit_transmission(old.clone());
        let mut next = cache.begin_batch(start);
        assert!(!cache.stage_result(&mut next, &result(json!({"count": 1})), false).unwrap());
        let mut restarted = TelemetryStateCache::new(300);
        restarted.commit_transmission(old);
        assert!(restarted.snapshot_due(restarted.origin));
    }
}
