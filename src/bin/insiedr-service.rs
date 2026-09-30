use insiedr_core::collectors::activity::ActivityCollector;
use insiedr_core::collectors::browser_history::BrowserHistoryCollector;
use insiedr_core::collectors::clipboard::ClipboardCollector;
use insiedr_core::collectors::decoy::DecoyCollector;
use insiedr_core::collectors::dns::DnsCollector;
use insiedr_core::collectors::driver_monitor::DriverMonitorCollector;
use insiedr_core::collectors::email::EmailCollector;
use insiedr_core::collectors::file_integrity::FileIntegrityCollector;
use insiedr_core::collectors::keystroke_biometrics::KeystrokeBiometricsCollector;
use insiedr_core::collectors::logon::LogonCollector;
use insiedr_core::collectors::lsass::LsassCollector;
use insiedr_core::collectors::named_pipe::NamedPipeCollector;
use insiedr_core::collectors::network::NetworkCollector;
use insiedr_core::collectors::persistence::PersistenceCollector;
use insiedr_core::collectors::process_watcher::ProcessWatcherCollector;
use insiedr_core::collectors::short_term_edr::ShortTermEdrCollector;
use insiedr_core::collectors::usb_devices::UsbDeviceCollector;
use insiedr_core::collectors::usn::UsnCollector;
use insiedr_core::collectors::wmi_activity::WmiActivityCollector;
use insiedr_core::collectors::memory_scanner::MemoryScannerCollector;
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
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("=== InsiEDR Enterprise Agent v2.0.0 (Native Rust Sensor) ===");

    // 0. Enable Windows Enterprise EDR Privileges (SeDebugPrivilege, SeSecurityPrivilege, SeBackupPrivilege)
    insiedr_core::core::privileges::enable_core_edr_privileges();
    println!("[Privileges] Windows SeDebugPrivilege, SeSecurityPrivilege & SeBackupPrivilege enabled");

    // 1. Enforce Resource Governor (Max 3.00% CPU)
    if let Err(e) = set_cpu_rate_cap(300) {
        eprintln!("[Governor] Note: Job Object CPU rate limiting skipped: {e}");
    } else {
        println!("[Governor] Windows Job Object CPU rate cap enforced at 3.00%");
    }

    let config = AgentConfig::default();
    println!("[Config] Agent ID: {}", config.agent_id);
    println!("[Config] Server URL: {}", config.server_url);
    println!("[Config] Crypto Scheme: {}", config.crypto_scheme);

    // 1.5. Initialize Autonomous On-Sensor Detection & Containment Engine
    let autonomous_engine = Arc::new(insiedr_core::engine::AutonomousEngine::new(
        config.server_url.clone(),
    ));
    println!("[Engine] Autonomous On-Sensor IOA Engine active (Sub-ms Kill & Isolation)");

    // 1.6. Initialize Real-Time Kernel ETW Streaming & Attach Autonomous IOA Listener
    let _etw_session = insiedr_core::etw::initialize_etw();
    if let Some(ref session) = _etw_session {
        println!("[ETW] Real-time Kernel ETW Session active (Process & DNS streams)");
        let mut rx = session.subscribe();
        let engine_clone = autonomous_engine.clone();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                if let insiedr_core::etw::types::EtwEvent::ProcessStart(ps) = event {
                    if let Some(alert) = engine_clone.evaluate_process_start(&ps) {
                        eprintln!("[AUTONOMOUS CONTAINMENT] Real-Time ETW IOA Intercepted: {:?}", alert);
                    }
                }
            }
        });
    } else {
        println!("[ETW] Running in user-mode snapshot baseline mode");
    }

    // 1.7. Spawn Session 0 IPC Named Pipe Server for In-Process AMSI Provider & Broker
    let _ipc_engine = autonomous_engine.clone();
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
                                            println!("[AMSI-IPC] Received in-process AMSI alert: {}", msg_str.trim());
                                        }
                                    }
                                }
                            }
                            server.disconnect();
                        });
                    }
                }
                Err(e) => {
                    eprintln!("[AMSI-IPC] Named Pipe server creation warning: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    });
    println!("[AMSI-IPC] Named Pipe Server active for In-Process AMSI telemetry ({})", insiedr_core::core::ipc::IPC_PIPE_NAME);

    // 2. Initialize SQLite WAL Spooler
    let spooler = Arc::new(SqliteSpooler::new(&config.spool_db_path, 50_000)?);
    println!("[Spool] SQLite WAL queue initialized (spool.db)");

    // 3. Initialize Transport Client
    let transport = Arc::new(InsiTransportClient::new(&config.server_url));

    // 4. Initialize Full Enterprise Telemetry Collector Suite (19 Collectors)
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(LogonCollector::new()),
        Box::new(NetworkCollector::new()),
        Box::new(UsbDeviceCollector::new()),
        Box::new(BrowserHistoryCollector::new()),
        Box::new(KeystrokeBiometricsCollector::new()),
        Box::new(ActivityCollector::new()),
        Box::new(ClipboardCollector::new()),
        Box::new(NamedPipeCollector::new()),
        Box::new(DriverMonitorCollector::new()),
        Box::new(PersistenceCollector::new()),
        Box::new(DecoyCollector::new()),
        Box::new(UsnCollector::new()),
        Box::new(ProcessWatcherCollector::new()),
        Box::new(FileIntegrityCollector::new()),
        Box::new(ShortTermEdrCollector::new()),
        Box::new(EmailCollector::new()),
        Box::new(DnsCollector::new()),
        Box::new(LsassCollector::new()),
        Box::new(WmiActivityCollector::new()),
        Box::new(MemoryScannerCollector::new()),
    ];

    let once_mode = env::args().any(|arg| arg == "--once");

    // Single run or loop
    loop {
        let payload_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // Step A: Collect Telemetry
        let mut telemetry = TelemetryPayload::with_username(
            config.agent_id.clone(),
            config.hostname.clone(),
            config.username.clone(),
            payload_id.clone(),
            now.clone(),
        );

        for c in &collectors {
            let res = c.collect();
            // Real-time autonomous containment hooks
            if res.name == "memory-scanner" {
                if let Some(sample) = res.metrics.get("sample_threats").and_then(|s| s.as_array()) {
                    for threat_val in sample {
                        if let Ok(threat) = serde_json::from_value::<insiedr_core::collectors::memory_scanner::MemoryThreat>(threat_val.clone()) {
                            let alert = autonomous_engine.evaluate_memory_threat(&threat);
                            eprintln!("[AUTONOMOUS CONTAINMENT] Incident Triggered: {:?}", alert);
                        }
                    }
                }
            } else if res.name == "decoy-monitor" {
                if res.metrics.get("threat_triggered").and_then(|t| t.as_bool()) == Some(true) {
                    let alert = autonomous_engine.evaluate_decoy_tampering("C:\\Users\\Public\\Admin_Passwords.xlsx", None);
                    eprintln!("[AUTONOMOUS CONTAINMENT] Decoy Tampering Incident Triggered: {:?}", alert);
                }
            }
            println!("[Collector] Harvested: {} (metrics: {})", res.name, res.metrics);
            telemetry.add_collector(res);
        }

        let plaintext_json = telemetry.to_canonical_json_bytes()?;

        // Step B: Encrypt Envelope matching InsiEDR Server
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

            WireEnvelope::new_hpke(
                payload_id.clone(),
                config.key_id.clone(),
                encapped_b64,
                nonce_b64,
                cipher_b64,
                now,
            )
        } else {
            let aes = AesGcmEngine::new(&config.aes_key_bytes)?;
            let (nonce_b64, cipher_b64) = aes.encrypt(&plaintext_json)?;

            custom_headers.insert(HEADER_CRYPTO_SCHEME.to_string(), "aes-256-gcm".to_string());

            WireEnvelope::new_aesgcm(
                payload_id.clone(),
                config.key_id.clone(),
                nonce_b64,
                cipher_b64,
                now,
            )
        };

        let envelope_json = serde_json::to_string(&envelope)?;

        // Step C: Transmit Telemetry
        println!("[Transport] Emitting telemetry envelope {} to /api/logs...", payload_id);
        match transport.send_telemetry(&envelope_json, &custom_headers).await {
            Ok(_) => {
                println!("[Transport] Envelope successfully delivered to server (HTTP 200/202)");
                // Automatically drain pending offline backlog from SQLite WAL spool
                if let Ok(backlog) = spooler.peek_batch(10) {
                    for rec in backlog {
                        if let Ok(hdrs) = serde_json::from_str::<HashMap<String, String>>(&rec.headers_json) {
                            if transport.send_telemetry(&rec.envelope_json, &hdrs).await.is_ok() {
                                println!("[Spool] Successfully uploaded backlog record {}", rec.payload_id);
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
                eprintln!("[Transport] Transmission failed: {e}. Enqueuing to SQLite WAL spool.");
                let headers_json = serde_json::to_string(&custom_headers)?;
                let _ = spooler.enqueue(&payload_id, &envelope_json, &headers_json, 1);
            }
        }

        // Step D: Send Heartbeat & Process Control Plane Downlink Tasks
        let hb_req = HeartbeatRequest {
            agent_id: config.agent_id.clone(),
            hostname: config.hostname.clone(),
            ip_address: "127.0.0.1".to_string(),
            agent_version: "2.0.0".to_string(),
            status: "healthy".to_string(),
            metrics: HostMetrics {
                cpu_percent: 0.2,
                memory_mb: 8.5,
                spool_queue_depth: spooler.queue_depth(),
            },
            config_version: "v1.0".to_string(),
        };

        if let Ok(hb_resp) = transport.send_heartbeat(&hb_req).await {
            println!("[ControlPlane] Heartbeat acknowledged by server. Tasks: {}", hb_resp.pending_tasks.len());
            for task in hb_resp.pending_tasks {
                println!("[ControlPlane] Executing remote task: {} (ID: {})", task.command, task.task_id);
                let (exit_code, msg) = execute_remote_task(&task, "127.0.0.1");

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

        if once_mode {
            println!("[Execution] Completed one-shot collection cycle (--once). Exiting.");
            std::process::exit(0);
        }

        tokio::time::sleep(Duration::from_secs(config.heartbeat_interval_secs)).await;
    }

    #[allow(unreachable_code)]
    Ok(())
}
