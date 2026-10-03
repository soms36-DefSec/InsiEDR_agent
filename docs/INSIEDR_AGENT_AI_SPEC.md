# InsiEDR-Agent: Specific AI Engineering & Prompt Guidebook
> **Codebase**: `d:\Projects\AISH\InsiEDR-agent`  
> **Tech Stack**: Rust 2021, Windows API (`windows` crate v0.58), `tokio`, `rusqlite` (WAL), `ring` / `x25519-dalek` (HPKE), `reqwest` (rustls)  
> **Binaries**: `insiedr-service.rs` (Windows Service), `insiedr-broker.rs` (IPC Broker), `insiedr-watchdog.rs` (Watchdog), `crates/insiedr-amsi` (AMSI Provider)

---

## 1. Concrete Architecture & Subsystem Map

Any AI agent operating on `InsiEDR-agent` must be aware of the exact file layout and system boundaries:

```
src/
├── bin/
│   ├── insiedr-service.rs       # Primary Windows Service entry point & event dispatch
│   ├── insiedr-broker.rs        # IPC communication broker between service & collectors
│   ├── insiedr-watchdog.rs      # Independent watchdog daemon monitoring service health
│   └── check_ts.rs              # Timestamp integrity verification utility
├── core/
│   ├── governor.rs              # CPU rate capping using Windows Job Objects (hard cap basis points)
│   ├── defense.rs               # Windows Service DACL hardening via SDDL (prevents service stoppage)
│   ├── privileges.rs           # SeDebugPrivilege, SeSecurityPrivilege acquisition & auditing
│   ├── ipc.rs                  # Named Pipe client/server with security descriptors
│   ├── config.rs               # Agent runtime configuration parsing & validation
│   └── state_cache.rs          # In-memory transient state & deduplication cache
├── crypto/
│   ├── hpke.rs                 # Hybrid Public Key Encryption (X25519 ECDH + HKDF + ChaCha20/AES)
│   ├── aesgcm.rs               # AES-256-GCM authenticated encryption via `ring`
│   └── dpapi.rs                # Windows Data Protection API (DPAPI) for persistent secret storage
├── etw/
│   ├── session.rs              # Windows Event Tracing (ETW) session management
│   ├── hub.rs                  # Central ETW event distributor & dispatcher
│   ├── parser.rs               # ETW event schema decoding (Process, Network, Thread, ImageLoad)
│   └── types.rs                # Strongly-typed ETW telemetry definitions
├── collectors/                 # 20 Specialized Telemetry Collectors
│   ├── process_watcher.rs      # Process creation & termination monitoring
│   ├── network.rs              # Socket binding, connections & DNS resolution
│   ├── lsass.rs                # LSASS memory access & handle opening detection
│   ├── memory_scanner.rs       # In-memory injection, shellcode & unbacked RWX scanner
│   ├── file_integrity.rs       # Critical filesystem modification tracking
│   ├── usn.rs                  # NTFS USN Journal event reader
│   ├── driver_monitor.rs       # Kernel driver load events & signature verification
│   ├── named_pipe.rs           # Named Pipe creation & connection tracking
│   ├── wmi_activity.rs         # WMI event consumer & persistence detection
│   ├── keystroke_biometrics.rs # Behavioral cadence collector
│   ├── decoy.rs                # Honey-token & decoy file tripwires
│   └── clipboard.rs, dns.rs, email.rs, logon.rs, persistence.rs, semantics.rs, short_term_edr.rs, usb_devices.rs
├── control/                    # Active Remediation & Incident Response
│   ├── isolate.rs              # Host network isolation via Windows Filtering Platform (WFP)
│   ├── terminate.rs            # Forced process & tree termination via Win32 APIs
│   ├── lock.rs                 # Workstation session lock (LockWorkStation)
│   └── rollback.rs             # Volume Shadow Copy (VSS) & file recovery
├── spool/
│   └── sqlite_spool.rs         # Bundled SQLite in WAL mode for persistent offline ring-buffering
├── transport/
│   └── client.rs               # Asynchronous HTTPS client (reqwest + rustls) with backoff & jitter
└── protocol/
    ├── envelope.rs             # Cryptographic telemetry envelope definition
    ├── payload.rs              # Structured event payload schemas
    └── heartbeat.rs            # Agent health & telemetry heartbeat frame
```

---

## 2. The 6 Engineering Perspectives (Specific to Rust & Windows Native EDR)

Every AI agent reviewing or modifying this codebase must adhere strictly to these rules:

### 1. Architecture
- **Multi-Process Segregation**: `insiedr-service` is guarded by `insiedr-watchdog`. IPC communication between them and collectors occurs strictly over secure Named Pipes (`src/core/ipc.rs`).
- **Bounded Channel Queues**: Event pipelines must use bounded channels (e.g., `tokio::sync::mpsc::channel(capacity)`). Unbounded channels are strictly forbidden to prevent Out-Of-Memory (OOM) under event storms.
- **Async Cancellation Safety**: All `tokio::select!` branches must be cancellation-safe. Dropping an incomplete branch must not leak OS handles (`HANDLE`, `SC_HANDLE`) or leave SQLite transactions in an undefined state.

### 2. Design
- **Error Handling**: Use structured `Result<T, InsiError>`. Never use `.unwrap()` or `.expect()` in production paths (`src/lib.rs`, `src/collectors/`, `src/spool/`). Use proper error propagation (`?`) or fallbacks.
- **Resource Cleanup**: Every Windows `HANDLE` must be wrapped in an RAII guard that calls `CloseHandle` in its `Drop` implementation to prevent handle leaks.

### 3. Security & Anti-Tampering
- **Service DACL Protection**: `src/core/defense.rs` enforces SDDL `D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPLORC;;;BA)(A;;CCLCSWRPWPDTLORC;;;SY)`. Any changes must ensure local Administrators cannot terminate or tamper with the service without breaking the watchdog.
- **Key Protection**: Symmetric keys must never reside in plaintext on disk; they must be sealed using Windows DPAPI (`src/crypto/dpapi.rs`) or encrypted via HPKE (`src/crypto/hpke.rs`).
- **Memory Zeroization**: Cryptographic buffers must implement `zeroize::ZeroizeOnDrop` to purge sensitive bytes upon deallocation.

### 4. Reliability & Host Stability
- **Zero Kernel/OS Impact**: The sensor must NEVER cause a Blue Screen of Death (BSOD) or trigger OS kernel instability.
- **Hard CPU Capping**: `src/core/governor.rs` sets a hard CPU quota via Windows Job Objects (`set_cpu_rate_cap(300)` = 3.00% max). Any new worker threads must be assigned to this Job Object.
- **Offline Spool Resiliency**: `src/spool/sqlite_spool.rs` uses SQLite WAL mode (`PRAGMA journal_mode=WAL;`). When offline capacity limit is reached, a FIFO drop policy must drop low-priority telemetry while preserving critical alerts.

### 5. Adaptability
- **Dynamic Policy Reload**: Collectors must be toggleable at runtime without terminating the agent process.
- **OS Version Compatibility**: Guard OS-specific API calls (`windows` crate) with runtime Windows version checks (e.g., Windows 10/11 vs Windows Server 2019/2022).

### 6. Developer-Friendly Code
- **Idiomatic Rust**: Adhere to `cargo clippy -- -D warnings`.
- **Instrumentation**: Log events with structured key-value pairs using the `log` crate. Avoid printing raw sensitive PII or passwords.
- **Deterministic Mocking**: All tests must run hermetically without requiring elevation (Administrator privileges) unless explicitly isolated in integration tests.

---

## 3. Specific Agent Master Prompts (Ready to Copy)

### Agent Prompt 1: Codebase Analysis & Diagnostics
```markdown
### TASK: INSIEDR-AGENT SUBSYSTEM AUDIT & ROOT CAUSE ANALYSIS

#### AGENT CONTEXT:
You are an expert Windows Native Rust Systems Engineer auditing `InsiEDR-agent` (Windows API, Tokio, SQLite WAL, Win32 ETW, HPKE/AES-GCM).

#### SCOPE OF ANALYSIS:
- Target Subsystem / File: {{INSERT_FILE_E_G_src_collectors_lsass_rs}}
- Reported Behavior / Goal: {{INSERT_ISSUE_OR_BEHAVIOR}}

#### AUDIT CHECKLIST:
1. **Windows API & Handle Safety**:
   - Are Win32 `HANDLE`, `SC_HANDLE`, or registry handles leaked? Are they closed via RAII `Drop`?
   - Are pointers passed to Windows FFI guaranteed to be valid and properly aligned?
2. **Concurrency & Tokio Runtime**:
   - Are any blocking OS calls (e.g., synchronous file IO, Sleep, blocking IPC) executed directly inside async Tokio worker tasks without `tokio::task::spawn_blocking`?
   - Are channels bounded? Is there risk of deadlock in `tokio::select!`?
3. **Resource & Governor Limits**:
   - Does this component respect the CPU rate cap in `src/core/governor.rs`?
   - Does it allocate unbounded vectors or buffers during event bursts?
4. **Security & Anti-Tamper**:
   - Does it expose vulnerable Named Pipe endpoints in `src/core/ipc.rs`?
   - Are cryptographic secrets zeroized upon drop?
5. **Panics & Error Handling**:
   - Are there any `.unwrap()`, `.expect()`, or unreachable assertions that could crash `insiedr-service.rs`?

#### REQUIRED DELIVERABLE:
1. **Executive Assessment**: State if the code violates any of the 6 InsiEDR pillars.
2. **Defect Matrix**: Table detailing File:Line, Severity, Category, and Technical Impact.
3. **Step-by-Step Root Cause Analysis**: Precise trace of failure conditions.
4. **Proposed Remediation Architecture**: Architectural guidance before drafting the plan.
```

---

### Agent Prompt 2: Test Suite & Fuzzing Engine
```markdown
### TASK: INSIEDR-AGENT TEST SUITE & MOCK HARNESS GENERATION

#### AGENT CONTEXT:
You are a Systems QA Engineer writing tests for `InsiEDR-agent` in Rust.

#### SCOPE:
- Target Module: {{INSERT_MODULE_E_G_src_spool_sqlite_spool_rs}}
- Related Files: {{INSERT_RELATED_FILES}}

#### TESTING REQUIREMENTS:
1. **Hermetic Unit Tests**:
   - Test logic without requiring administrator elevation.
   - Use in-memory SQLite (`:memory:`) or temporary directories for file/spool tests.
2. **Failure Injection & Edge Cases**:
   - Simulate sudden process termination / crash recovery on SQLite WAL spool.
   - Test corrupted or malformed ETW event payloads in `src/etw/parser.rs`.
   - Test encryption/decryption round-trip with corrupted ciphertexts or invalid keys.
3. **Concurrency & Backpressure**:
   - Spawn multiple threads pushing events simultaneously to test thread safety.
   - Verify that buffer saturation triggers FIFO eviction without panicking.
4. **Zero-Panic Verification**:
   - Pass invalid UTF-8, null bytes, and out-of-range timestamps to verify graceful error return.

#### REQUIRED DELIVERABLE:
1. **Test Strategy Summary**: Table mapping test cases to risk areas.
2. **Rust Test Code (`#[cfg(test)] mod tests`)**: Complete, idiomatic test implementation.
3. **Verification Command**: Exact `cargo test` command (e.g. `cargo test --bin insiedr-service -- --nocapture`).
```

---

### Agent Prompt 3: Specific Implementation Plan Generator
```markdown
### TASK: INSIEDR-AGENT PHASED IMPLEMENTATION PLAN

#### AGENT CONTEXT:
You are the Lead Systems Architect for `InsiEDR-agent`. Create an implementation plan for the requested feature or fix before modifying code.

#### SCOPE:
- Problem Statement: {{INSERT_PROBLEM_STATEMENT}}
- Analysis Summary: {{INSERT_ANALYSIS_SUMMARY}}

#### PLAN REQUIREMENTS:
1. **Impacted Subsystems**: Identify exact files across `src/core/`, `src/collectors/`, `src/etw/`, `src/spool/`, `src/crypto/`, `src/transport/`, or `src/control/`.
2. **6-Pillar Risk Evaluation**:
   - Check Windows API compatibility, CPU governor compliance, and panic safety.
3. **Phased Execution Roadmap**:
   - **Phase 1: Interfaces & Types**: Define new structs/enums in `src/protocol/` or module types.
   - **Phase 2: Core Logic**: Implement the change cleanly with RAII handle guards and error propagation.
   - **Phase 3: Integration & Spooling**: Connect with `sqlite_spool.rs` or `transport/client.rs`.
   - **Phase 4: Unit & Stress Tests**: Write hermetic tests and verify memory bounds.
4. **Rollback & Safety Strategy**:
   - How to safely revert or disable this collector/logic if an unexpected host crash occurs.
5. **Exact File Modification Table**: Target file path, operation (Create/Modify), and description.
```

---

### Agent Prompt 4: Surgical Bug Fix & Implementation
```markdown
### TASK: INSIEDR-AGENT SURGICAL CODE IMPLEMENTATION

#### AGENT CONTEXT:
You are an expert Rust Systems Developer implementing an approved plan for `InsiEDR-agent`.

#### INPUT:
- Approved Plan: {{INSERT_APPROVED_PLAN}}
- Target Component: {{INSERT_TARGET_FILE_OR_MODULE}}

#### IMPLEMENTATION RULES:
1. **Never use `.unwrap()` or `.expect()`** in production code. Always use `?` or handle errors with `match`/`if let`.
2. Wrap all Win32 `HANDLE` types in RAII guards to ensure `CloseHandle` is called automatically.
3. Ensure all Tokio async functions avoid blocking calls; use `tokio::task::spawn_blocking` for synchronous disk/Win32 calls.
4. Run `cargo clippy` standards in your head: idiomatic Rust, minimal allocations, no unnecessary clones.
5. Provide complete, contiguous code blocks ready to be inserted.
```
