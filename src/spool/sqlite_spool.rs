use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult, TransactionBehavior};
use std::path::Path;
use std::sync::Mutex;

pub struct SpooledRecord {
    pub id: i64,
    pub payload_id: String,
    pub envelope_json: String,
    pub headers_json: String,
    pub retry_count: i32,
    /// ACK-dependent state to commit only after this exact envelope is accepted.
    /// Records written by older agents do not carry this metadata.
    pub state_json: Option<String>,
}

pub struct SqliteSpooler {
    conn: Mutex<Connection>,
    max_records: usize,
}

impl SqliteSpooler {
    pub fn new<P: AsRef<Path>>(db_path: P, max_records: usize) -> SqlResult<Self> {
        if let Some(parent) = db_path.as_ref().parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut conn = Connection::open(db_path)?;

        // Enterprise SQLite Performance & Durability Configuration
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;",
        )?;

        // Serialize schema upgrades with other spool handles. Existing envelopes
        // remain replayable when upgrading from a schema without ACK metadata.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS telemetry_spool (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 payload_id TEXT UNIQUE NOT NULL,
                 envelope_json TEXT NOT NULL,
                 headers_json TEXT NOT NULL,
                 priority INTEGER DEFAULT 1,
                 created_at TEXT NOT NULL,
                 retry_count INTEGER DEFAULT 0,
                 state_json TEXT
             );
             
             CREATE INDEX IF NOT EXISTS idx_spool_created ON telemetry_spool(created_at);
             CREATE INDEX IF NOT EXISTS idx_spool_priority ON telemetry_spool(priority DESC, id ASC);",
        )?;
        let has_state_column = {
            let mut stmt = tx.prepare("PRAGMA table_info(telemetry_spool)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                found |= column? == "state_json";
            }
            found
        };
        if !has_state_column {
            tx.execute_batch("ALTER TABLE telemetry_spool ADD COLUMN state_json TEXT;")?;
        }
        tx.commit()?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_records,
        })
    }

    /// Enqueues an encrypted envelope to the SQLite WAL spool with a priority level (1=normal, 2=high).
    pub fn enqueue(
        &self,
        payload_id: &str,
        envelope_json: &str,
        headers_json: &str,
        priority: i32,
    ) -> SqlResult<()> {
        self.enqueue_with_state(payload_id, envelope_json, headers_json, priority, None)
    }

    /// Durably stages the exact envelope and its ACK-dependent state together.
    /// A full spool rejects new records instead of evicting unacknowledged events.
    pub fn enqueue_with_state(
        &self,
        payload_id: &str,
        envelope_json: &str,
        headers_json: &str,
        priority: i32,
        state_json: Option<&str>,
    ) -> SqlResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT envelope_json, headers_json, state_json FROM telemetry_spool WHERE payload_id = ?1",
                params![payload_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((envelope, headers, state)) = existing {
            if envelope == envelope_json
                && headers == headers_json
                && state.as_deref() == state_json
            {
                // Re-staging identical bytes must not reset identity or retries,
                // including when the queue is already at capacity.
                return Ok(());
            }
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some("payload_id already has different unacknowledged telemetry".into()),
            ));
        }

        let count: usize =
            tx.query_row("SELECT COUNT(*) FROM telemetry_spool", [], |r| r.get(0))?;

        if count >= self.max_records {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                Some("telemetry spool is full; unacknowledged records were preserved".into()),
            ));
        }

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        tx.execute(
            "INSERT INTO telemetry_spool
             (payload_id, envelope_json, headers_json, priority, created_at, retry_count, state_json)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![payload_id, envelope_json, headers_json, priority, now, state_json],
        )?;
        tx.commit()?;

        Ok(())
    }

    /// Fetches up to `limit` pending records to transmit.
    pub fn peek_batch(&self, limit: usize) -> SqlResult<Vec<SpooledRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload_id, envelope_json, headers_json, retry_count, state_json
             FROM telemetry_spool 
             ORDER BY priority DESC, id ASC 
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(SpooledRecord {
                id: row.get(0)?,
                payload_id: row.get(1)?,
                envelope_json: row.get(2)?,
                headers_json: row.get(3)?,
                retry_count: row.get(4)?,
                state_json: row.get(5)?,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    /// Deletes a successfully acknowledged payload from the spool.
    pub fn acknowledge(&self, id: i64) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM telemetry_spool WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Deletes a successfully acknowledged payload by its stable wire identity.
    pub fn acknowledge_payload(&self, payload_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM telemetry_spool WHERE payload_id = ?1",
            params![payload_id],
        )?;
        Ok(())
    }

    /// Increments retry count on transmission failure.
    pub fn increment_retry(&self, id: i64) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE telemetry_spool SET retry_count = retry_count + 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Returns the current number of pending items in the spool.
    pub fn queue_depth(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM telemetry_spool", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spooler_lifecycle() {
        let spooler = SqliteSpooler::new(":memory:", 100).unwrap();
        assert_eq!(spooler.queue_depth(), 0);

        spooler
            .enqueue("payload-1", "{\"envelope\": 1}", "{}", 1)
            .unwrap();
        assert_eq!(spooler.queue_depth(), 1);

        let batch = spooler.peek_batch(10).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload_id, "payload-1");

        spooler.acknowledge(batch[0].id).unwrap();
        assert_eq!(spooler.queue_depth(), 0);
    }

    #[test]
    fn full_spool_preserves_events_instead_of_shedding_for_priority() {
        let spooler = SqliteSpooler::new(":memory:", 1).unwrap();
        spooler.enqueue("original", "event-bytes", "{}", 1).unwrap();

        let error = spooler
            .enqueue("urgent", "urgent-bytes", "{}", 2)
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull)
        );
        let pending = spooler.peek_batch(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payload_id, "original");
        assert_eq!(pending[0].envelope_json, "event-bytes");

        spooler.acknowledge_payload("original").unwrap();
        spooler.enqueue("urgent", "urgent-bytes", "{}", 2).unwrap();
        assert_eq!(spooler.peek_batch(1).unwrap()[0].payload_id, "urgent");
    }

    #[test]
    fn duplicate_identity_preserves_bytes_state_and_retry_history() {
        let spooler = SqliteSpooler::new(":memory:", 1).unwrap();
        let state = Some("{\"generation\":7}");
        spooler
            .enqueue_with_state("same-id", "original", "headers", 1, state)
            .unwrap();
        let id = spooler.peek_batch(1).unwrap()[0].id;
        spooler.increment_retry(id).unwrap();
        spooler
            .enqueue_with_state("same-id", "original", "headers", 2, state)
            .unwrap();

        for (envelope, headers, metadata) in [
            ("changed", "headers", state),
            ("original", "changed", state),
            ("original", "headers", Some("{\"generation\":8}")),
            ("original", "headers", None),
        ] {
            assert!(spooler
                .enqueue_with_state("same-id", envelope, headers, 1, metadata)
                .is_err());
        }

        let record = &spooler.peek_batch(10).unwrap()[0];
        assert_eq!(record.id, id);
        assert_eq!(record.envelope_json, "original");
        assert_eq!(record.headers_json, "headers");
        assert_eq!(record.state_json.as_deref(), state);
        assert_eq!(record.retry_count, 1);
        assert_eq!(spooler.queue_depth(), 1);
    }

    #[test]
    fn legacy_database_migrates_and_ack_state_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "insiedr-spool-test-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE telemetry_spool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_id TEXT UNIQUE NOT NULL,
                    envelope_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    priority INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0
                );
                INSERT INTO telemetry_spool
                    (payload_id, envelope_json, headers_json, created_at, retry_count)
                    VALUES ('legacy-id', 'legacy-ciphertext', '{}', '2026-01-01', 3);",
            )
            .unwrap();
        }
        {
            let spooler = SqliteSpooler::new(&path, 10).unwrap();
            let old = &spooler.peek_batch(10).unwrap()[0];
            assert_eq!(old.envelope_json, "legacy-ciphertext");
            assert_eq!(old.retry_count, 3);
            assert_eq!(old.state_json, None);
            let synchronous: i32 = spooler
                .conn
                .lock()
                .unwrap()
                .query_row("PRAGMA synchronous", [], |row| row.get(0))
                .unwrap();
            assert_eq!(synchronous, 2);
            spooler
                .enqueue_with_state(
                    "new-id",
                    "new-ciphertext",
                    "new-headers",
                    1,
                    Some("{\"generation\":9}"),
                )
                .unwrap();
        }
        {
            let spooler = SqliteSpooler::new(&path, 10).unwrap();
            let pending = spooler.peek_batch(10).unwrap();
            assert_eq!(pending.len(), 2);
            assert_eq!(pending[1].envelope_json, "new-ciphertext");
            assert_eq!(pending[1].headers_json, "new-headers");
            assert_eq!(pending[1].state_json.as_deref(), Some("{\"generation\":9}"));
            spooler.acknowledge_payload("new-id").unwrap();
            assert_eq!(spooler.peek_batch(10).unwrap()[0].payload_id, "legacy-id");
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn zero_capacity_cannot_accept_a_record() {
        let spooler = SqliteSpooler::new(":memory:", 0).unwrap();
        assert!(spooler.enqueue("payload", "event", "{}", 1).is_err());
        assert_eq!(spooler.queue_depth(), 0);
    }
}
