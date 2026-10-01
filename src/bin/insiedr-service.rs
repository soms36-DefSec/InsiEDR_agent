#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use insiedr_core::collectors::activity::ActivityCollector;
use insiedr_core::collectors::file_integrity::FileIntegrityCollector;
use insiedr_core::collectors::keystroke_biometrics::KeystrokeBiometricsCollector;
use insiedr_core::collectors::logon::LogonCollector;
use insiedr_core::collectors::network::NetworkCollector;
use insiedr_core::collectors::process_watcher::ProcessWatcherCollector;
use insiedr_core::collectors::short_term_edr::ShortTermEdrCollector;
use insiedr_core::collectors::usb_devices::UsbDeviceCollector;
use insiedr_core::collectors::Collector;
use insiedr_core::control::execute_remote_task;
use insiedr_core::core::config::AgentConfig;
use insiedr_core::core::governor::set_cpu_rate_cap;
use insiedr_core::core::state_cache::{PendingState, TelemetryStateCache};
use insiedr_core::crypto::aesgcm::AesGcmEngine;
use insiedr_core::crypto::hpke::HpkeEngine;
use insiedr_core::protocol::envelope::WireEnvelope;
use insiedr_core::protocol::heartbeat::{HeartbeatRequest, HostMetrics, TaskResultPayload};
use insiedr_core::protocol::payload::TelemetryPayload;
use insiedr_core::protocol::{
    HEADER_AGENT_ID, HEADER_CRYPTO_SCHEME, HEADER_ENCAPPED_KEY, HEADER_KEY_ID, HEADER_PAYLOAD_ID,
    HEADER_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use insiedr_core::spool::sqlite_spool::SqliteSpooler;
use insiedr_core::transport::client::InsiTransportClient;
use std::collections::HashMap;
use std::env;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Resolves the machine's outbound LAN IP by probing a UDP route to the server.
/// No packet is actually sent — this is a routing-table lookup trick (zero network traffic).
fn resolve_local_ip(server_url: &str) -> String {
    // Strip scheme and path to extract host[:port]
    let host_part = server_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("8.8.8.8");

    // Build target: if no port in config, default to 80 for the routing probe
    let target = if host_part.contains(':') {
        host_part.to_string()
    } else {
        format!("{host_part}:80")
    };

    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect(&target).map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Heartbeats run separately so quiet telemetry and slow/retrying uploads do not
/// suppress fleet liveness or the existing server-command downlink.
async fn heartbeat_cycle(
    config: &AgentConfig,
    local_ip: &str,
    transport: &InsiTransportClient,
    spooler: &SqliteSpooler,
) {
    let hb_req = HeartbeatRequest {
        agent_id: config.agent_id.clone(),
        hostname: config.hostname.clone(),
        ip_address: local_ip.to_string(),
        agent_version: "2.0.0".to_string(),
        status: "healthy".to_string(),
        metrics: HostMetrics {
            cpu_percent: 0.2,
            memory_mb: 8.5,
            spool_queue_depth: spooler.queue_depth(),
        },
        config_version: "v1.0".to_string(),
    };
    match transport.send_heartbeat(&hb_req).await {
        Ok(hb_resp) => {
            for task in hb_resp.pending_tasks {
                println!("[ControlPlane] Executing server task: {} (id={})", task.command, task.task_id);
                let (exit_code, msg) = execute_remote_task(&task, local_ip);
                let result = TaskResultPayload {
                    agent_id: config.agent_id.clone(),
                    task_id: task.task_id,
                    status: if exit_code == 0 { "success".into() } else { "failed".into() },
                    exit_code,
                    message: msg,
                    timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                };
                let _ = transport.send_task_result(&result).await;
            }
        }
        Err(e) => eprintln!("[ControlPlane] Heartbeat failed (non-fatal): {e}"),
    }
}

/// Retry durable records even when this collection cycle produces no delta.
/// Malformed records stay queued for repair; they are never silently discarded.
async fn drain_spool(
    spooler: &SqliteSpooler,
    transport: &InsiTransportClient,
    state_cache: &mut TelemetryStateCache,
    next_upload_at: &mut Instant,
) {
    if Instant::now() < *next_upload_at { return; }
    let backlog = match spooler.peek_batch(10) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("[Spool] Unable to read pending telemetry: {e}");
            *next_upload_at = Instant::now() + Duration::from_secs(5);
            return;
        }
    };
    for rec in backlog {
        let headers = match serde_json::from_str::<HashMap<String, String>>(&rec.headers_json) {
            Ok(headers) => headers,
            Err(e) => {
                eprintln!("[Spool] Retaining malformed record {} for repair: {e}", rec.payload_id);
                *next_upload_at = Instant::now() + Duration::from_secs(60);
                return;
            }
        };
        if let Err(e) = transport.send_telemetry(&rec.envelope_json, &headers).await {
            eprintln!("[Transport] Pending envelope {} not acknowledged: {e}", rec.payload_id);
            if let Err(e) = spooler.increment_retry(rec.id) {
                eprintln!("[Spool] Could not update retry count: {e}");
            }
            let delay = 5u64 * (1u64 << rec.retry_count.clamp(0, 6) as u32);
            *next_upload_at = Instant::now() + Duration::from_secs(delay.min(300));
            return;
        }
        // Deleting only after the matching durable ACK makes a crash before this
        // point retry the same payload ID, which the server handles idempotently.
        if let Err(e) = spooler.acknowledge(rec.id) {
            eprintln!("[Spool] ACK received but record deletion failed: {e}");
            *next_upload_at = Instant::now() + Duration::from_secs(5);
            return;
        }
        if let Some(state_json) = rec.state_json {
            match serde_json::from_str::<PendingState>(&state_json) {
                Ok(pending) => state_cache.commit_transmission(pending),
                Err(e) => eprintln!("[Spool] State metadata invalid; baseline will be resent: {e}"),
            }
        }
        println!("[Transport] Acknowledged envelope {} (HTTP 202)", rec.payload_id);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("=== InsiEDR Enterprise Agent v2.0.0 (Native Rust Sensor) ===");

    // 0. Enable Windows Enterprise EDR Privileges (SeDebugPrivilege, SeSecurityPrivilege, SeBackupPrivilege)
    insiedr_core::core::privileges::enable_core_edr_privileges();
    println!("[Privileges] Windows SeDebugPrivilege, SeSecurityPrivilege & SeBackupPrivilege enabled");

    // 1. Enforce Resource Governor (Max 3.00% CPU via Windows Job Object hard cap)
    if let Err(e) = set_cpu_rate_cap(300) {
        eprintln!("[Governor] Note: Job Object CPU rate limiting skipped: {e}");
    } else {
        println!("[Governor] Windows Job Object CPU rate cap enforced at 3.00%");
    }

    let config = AgentConfig::default();
    println!("[Config] Agent ID  : {}", config.agent_id);
    println!("[Config] Server URL: {}", config.server_url);
    println!("[Config] Crypto    : {}", config.crypto_scheme);
    println!("[Config] Interval  : {}s", config.heartbeat_interval_secs);

    // Resolve real LAN IP for fleet-management heartbeat (server-side agent table)
    let local_ip = resolve_local_ip(&config.server_url);
    println!("[Config] Local IP  : {local_ip}");

    // 2. Initialize ETW Session — DATA ENRICHMENT ONLY, no autonomous containment.
    //    ETW buffers process/DNS events into EtwCollectorHub so collectors can read
    //    richer data. The agent NEVER kills processes or blocks networks based on ETW.
    //    All response actions are server-commanded via heartbeat task downlink (Step D).
    let _etw_session = insiedr_core::etw::initialize_etw();
    if let Some(ref session) = _etw_session {
        println!("[ETW] Real-time Kernel ETW Session active (data enrichment — no auto-containment)");
        let mut rx = session.subscribe();
        tokio::spawn(async move {
            // Passively drain events into hub buffer for collectors to consume each cycle.
            while let Ok(_event) = rx.recv().await {}
        });
    } else {
        println!("[ETW] Running in user-mode snapshot baseline mode");
    }

    // 3. Session 0 IPC Named Pipe Server (for insiedr-broker user-session telemetry bridge)
    tokio::task::spawn_blocking(move || {
        loop {
            match insiedr_core::core::ipc::NamedPipeServer::create(insiedr_core::core::ipc::IPC_PIPE_NAME) {
                Ok(server) => {
                    if server.wait_for_client() {
                        std::thread::spawn(move || {
                            while let Ok(msg_bytes) = server.read_message() {
                                if let Ok(msg_str) = std::str::from_utf8(&msg_bytes) {
                                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(msg_str) {
                                        if val.get("source").and_then(|s| s.as_str()) == Some("insiedr-amsi-provider") {
                                            println!("[AMSI-IPC] AMSI telemetry received: {}", msg_str.trim());
                                        }
                                    }
                                }
                            }
                            server.disconnect();
                        });
                    }
                }
                Err(e) => {
                    eprintln!("[AMSI-IPC] Named Pipe server warning: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    });
    println!("[AMSI-IPC] Named Pipe Server active ({})", insiedr_core::core::ipc::IPC_PIPE_NAME);

    // 4. Initialize SQLite WAL Spooler (offline-resilient buffering)
    let spooler = Arc::new(SqliteSpooler::new(&config.spool_db_path, 50_000)?);
    println!("[Spool] SQLite WAL queue initialized ({})", config.spool_db_path);

    // 5. Initialize Transport Client
    let transport = Arc::new(InsiTransportClient::new(&config.server_url));

    // 6. Initialize ML Dataset Telemetry Collector Suite (8 Core Behavioral Sensors)
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(KeystrokeBiometricsCollector::new()),
        Box::new(LogonCollector::new()),
        Box::new(ShortTermEdrCollector::new()),
        Box::new(ProcessWatcherCollector::new()),
        Box::new(FileIntegrityCollector::new()),
        Box::new(UsbDeviceCollector::new()),
        Box::new(NetworkCollector::new()),
        Box::new(ActivityCollector::new()),
    ];

    let once_mode = env::args().any(|arg| arg == "--once");

    let mut state_cache = TelemetryStateCache::new(config.snapshot_interval_secs);
    let mut next_upload_at = Instant::now();
    let mut collection_interval = tokio::time::interval(Duration::from_secs(config.heartbeat_interval_secs.max(1)));
    collection_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if !once_mode {
        let hb_config = config.clone();
        let hb_transport = transport.clone();
        let hb_spooler = spooler.clone();
        let hb_ip = local_ip.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(hb_config.heartbeat_interval_secs.max(1)));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                heartbeat_cycle(&hb_config, &hb_ip, &hb_transport, &hb_spooler).await;
            }
        });
    }

    // ─── Main Collection Loop ────────────────────────────────────────────────
    // DESIGN PRINCIPLE: This loop ONLY observes and transmits.
    // It NEVER takes autonomous action against the host system.
    // Response actions (isolate/kill/lock/rollback) happen ONLY in the heartbeat task
    // when the server explicitly commands them via heartbeat task downlink.
    loop {
        collection_interval.tick().await;
        drain_spool(&spooler, &transport, &mut state_cache, &mut next_upload_at).await;
        let payload_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut pending = state_cache.begin_batch(Instant::now());

        // Step A: Collect Telemetry — pure passive observation, zero host interference
        let mut telemetry = TelemetryPayload::with_username(
            config.agent_id.clone(),
            config.hostname.clone(),
            config.username.clone(),
            payload_id.clone(),
            now.clone(),
        );

        for c in &collectors {
            let mut res = c.collect();
            res.prune_null_fields();
            if res.hostname.is_empty() { res.hostname = config.hostname.clone(); }
            println!("[Collector] {} → {}", res.name, res.status);
            let bypass = !config.telemetry_optimization_enabled
                || c.is_security_event_collector()
                || c.has_security_events(&res)
                || c.has_active_threat(&res);
            if state_cache.stage_result(&mut pending, &res, bypass)? {
                telemetry.add_collector(res);
            }
        }

        if !telemetry.collectors.is_empty() {
        let plaintext_json = telemetry.to_canonical_json_bytes()?;

        // Step B: Encrypt Envelope (AES-256-GCM or HPKE)
        let mut custom_headers = HashMap::new();
        custom_headers.insert(HEADER_PROTOCOL_VERSION.to_string(), PROTOCOL_VERSION.to_string());
        custom_headers.insert(HEADER_AGENT_ID.to_string(), config.agent_id.clone());
        custom_headers.insert(HEADER_PAYLOAD_ID.to_string(), payload_id.clone());
        custom_headers.insert(HEADER_KEY_ID.to_string(), config.key_id.clone());

        let envelope = if config.crypto_scheme == "hpke" {
            let hpke = HpkeEngine::new(&config.hpke_server_pub_bytes, &config.key_id)?;
            let (encapped_b64, nonce_b64, cipher_b64) = hpke.encrypt(&plaintext_json)?;
            custom_headers.insert(HEADER_CRYPTO_SCHEME.to_string(), "hpke".to_string());
            custom_headers.insert(HEADER_ENCAPPED_KEY.to_string(), encapped_b64.clone());
            WireEnvelope::new_hpke(payload_id.clone(), config.key_id.clone(), encapped_b64, nonce_b64, cipher_b64, now)
        } else {
            let aes = AesGcmEngine::new(&config.aes_key_bytes)?;
            let (nonce_b64, cipher_b64) = aes.encrypt(&plaintext_json)?;
            custom_headers.insert(HEADER_CRYPTO_SCHEME.to_string(), "aes-256-gcm".to_string());
            WireEnvelope::new_aesgcm(payload_id.clone(), config.key_id.clone(), nonce_b64, cipher_b64, now)
        };

        let envelope_json = serde_json::to_string(&envelope)?;

        // Persist before network I/O, including the exact state staged in this envelope.
        let headers_json = serde_json::to_string(&custom_headers)?;
        let state_json = serde_json::to_string(&pending)?;
        loop {
            match spooler.enqueue_with_state(&payload_id, &envelope_json, &headers_json, 1, Some(&state_json)) {
                Ok(()) => break,
                Err(e) => {
                    // Apply backpressure while retaining this collected batch in memory.
                    // A full/damaged disk cannot support an unlimited no-loss guarantee.
                    eprintln!("[Spool] Cannot persist telemetry; collection paused until storage recovers: {e}");
                    drain_spool(&spooler, &transport, &mut state_cache, &mut next_upload_at).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        drain_spool(&spooler, &transport, &mut state_cache, &mut next_upload_at).await;
        } else {
            println!("[Telemetry] Unchanged baseline; telemetry upload suppressed");
        }

        if once_mode {
            heartbeat_cycle(&config, &local_ip, &transport, &spooler).await;
            println!("[Execution] One-shot cycle complete (--once). Exiting.");
            std::process::exit(0);
        }

    }

    #[allow(unreachable_code)]
    Ok(())
}
