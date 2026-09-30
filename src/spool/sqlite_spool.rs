use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;
use std::sync::Mutex;

pub struct SpooledRecord {
    pub id: i64,
    pub payload_id: String,
    pub envelope_json: String,
    pub headers_json: String,
    pub retry_count: i32,
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

        let conn = Connection::open(db_path)?;

        // Enterprise SQLite Performance & Durability Configuration
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             
             CREATE TABLE IF NOT EXISTS telemetry_spool (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 payload_id TEXT UNIQUE NOT NULL,
                 envelope_json TEXT NOT NULL,
                 headers_json TEXT NOT NULL,
                 priority INTEGER DEFAULT 1,
                 created_at TEXT NOT NULL,
                 retry_count INTEGER DEFAULT 0
             );
             
             CREATE INDEX IF NOT EXISTS idx_spool_created ON telemetry_spool(created_at);
             CREATE INDEX IF NOT EXISTS idx_spool_priority ON telemetry_spool(priority DESC, id ASC);",
        )?;

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
        let conn = self.conn.lock().unwrap();

        // Capacity guard: Priority shedding if exceeding max records
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM telemetry_spool",
            [],
            |r| r.get(0),
        )?;

        if count >= self.max_records {
            // Drop lowest priority, oldest records first
            conn.execute(
                "DELETE FROM telemetry_spool WHERE id IN (
                    SELECT id FROM telemetry_spool ORDER BY priority ASC, id ASC LIMIT ?1
                )",
                params![count - self.max_records + 1],
            )?;
        }

        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO telemetry_spool 
             (payload_id, envelope_json, headers_json, priority, created_at, retry_count) 
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![payload_id, envelope_json, headers_json, priority, now],
        )?;

        Ok(())
    }

    /// Fetches up to `limit` pending records to transmit.
    pub fn peek_batch(&self, limit: usize) -> SqlResult<Vec<SpooledRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload_id, envelope_json, headers_json, retry_count 
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
}

