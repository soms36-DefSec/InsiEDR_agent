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
use std::time::Duration;
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

    // ─── Main Collection Loop ────────────────────────────────────────────────
    // DESIGN PRINCIPLE: This loop ONLY observes and transmits.
    // It NEVER takes autonomous action against the host system.
    // Response actions (isolate/kill/lock/rollback) happen ONLY in Step D
    // when the server explicitly commands them via heartbeat task downlink.
    loop {
        let payload_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // Step A: Collect Telemetry — pure passive observation, zero host interference
        let mut telemetry = TelemetryPayload::with_username(
            config.agent_id.clone(),
            config.hostname.clone(),
            config.username.clone(),
            payload_id.clone(),
            now.clone(),
        );

        for c in &collectors {
            let res = c.collect();
            println!("[Collector] {} → {}", res.name, res.status);
            telemetry.add_collector(res);
        }

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

        // Step C: Transmit — with offline SQLite spool fallback
        println!("[Transport] Emitting telemetry envelope {} to /api/logs...", payload_id);
        match transport.send_telemetry(&envelope_json, &custom_headers).await {
            Ok(_) => {
                println!("[Transport] ✓ Envelope delivered (HTTP 200/202)");
                // Drain offline backlog in batches of 10
                if let Ok(backlog) = spooler.peek_batch(10) {
                    for rec in backlog {
                        if let Ok(hdrs) = serde_json::from_str::<HashMap<String, String>>(&rec.headers_json) {
                            if transport.send_telemetry(&rec.envelope_json, &hdrs).await.is_ok() {
                                println!("[Spool] ✓ Backlog record {} uploaded", rec.payload_id);
                                let _ = spooler.acknowledge(rec.id);
                            } else {
                                let _ = spooler.increment_retry(rec.id);
                                break;
                            }
                        } else {
                            let _ = spooler.acknowledge(rec.id);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[Transport] ✗ Transmission failed: {e} — queuing to spool");
                let headers_json = serde_json::to_string(&custom_headers)?;
                let _ = spooler.enqueue(&payload_id, &envelope_json, &headers_json, 1);
            }
        }

        // Step D: Heartbeat — the ONLY source of response actions on this agent.
        //   Server can send: isolate_host, unisolate_host, kill_process,
        //                    lock_workstation, create_shadow, rollback_directory.
        //   The agent executes ONLY what the server commands here.
        let hb_req = HeartbeatRequest {
            agent_id: config.agent_id.clone(),
            hostname: config.hostname.clone(),
            ip_address: local_ip.clone(),
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
                let task_count = hb_resp.pending_tasks.len();
                if task_count > 0 {
                    println!("[ControlPlane] Server dispatched {task_count} task(s)");
                }
                for task in hb_resp.pending_tasks {
                    println!("[ControlPlane] Executing server task: {} (id={})", task.command, task.task_id);
                    let (exit_code, msg) = execute_remote_task(&task, &local_ip);
                    println!("[ControlPlane] Result: exit={exit_code} — {msg}");

                    let result = TaskResultPayload {
                        agent_id: config.agent_id.clone(),
                        task_id: task.task_id,
                        status: if exit_code == 0 { "success".into() } else { "failed".into() },
                        exit_code,
                        message: msg,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    let _ = transport.send_task_result(&result).await;
                }
            }
            Err(e) => {
                // Heartbeat failure is non-fatal — agent continues collecting and spooling
                eprintln!("[ControlPlane] Heartbeat failed (non-fatal): {e}");
            }
        }

        if once_mode {
            println!("[Execution] One-shot cycle complete (--once). Exiting.");
            std::process::exit(0);
        }

        tokio::time::sleep(Duration::from_secs(config.heartbeat_interval_secs)).await;
    }

    #[allow(unreachable_code)]
    Ok(())
}
