use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::collectors::memory_scanner::MemoryThreat;
use crate::control::isolate::isolate_host;
use crate::control::lock::lock_workstation;
use crate::control::terminate::terminate_process_by_pid;
use crate::engine::rules::{evaluate_command_line, BUILTIN_RULES, ContainmentAction, DetectionRule, RuleSeverity};
use crate::etw::types::EtwProcessStart;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub alert_id: String,
    pub timestamp: DateTime<Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub mitre_technique: String,
    pub severity: RuleSeverity,
    pub offending_pid: u32,
    pub process_name: String,
    pub evidence: String,
    pub action_taken: String,
    pub containment_success: bool,
}

pub struct AutonomousEngine {
    server_ip: String,
    alert_history: Arc<Mutex<Vec<SecurityAlert>>>,
}

impl AutonomousEngine {
    pub fn new(server_ip: String) -> Self {
        Self {
            server_ip,
            alert_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn evaluate_process_start(&self, ps: &EtwProcessStart) -> Option<SecurityAlert> {
        if let Some(rule) = evaluate_command_line(&ps.command_line) {
            let alert = self.execute_containment(
                rule,
                ps.pid,
                &ps.image_name,
                &ps.command_line,
            );
            return Some(alert);
        }
        None
    }

    pub fn evaluate_memory_threat(&self, threat: &MemoryThreat) -> SecurityAlert {
        let rule = crate::engine::rules::get_rule_by_id("IOA-003").unwrap_or(&BUILTIN_RULES[2]);
        self.execute_containment(
            rule,
            threat.pid,
            &threat.process_name,
            &threat.details,
        )
    }

    pub fn evaluate_decoy_tampering(&self, decoy_path: &str, pid: Option<u32>) -> SecurityAlert {
        let rule = crate::engine::rules::get_rule_by_id("IOA-002").unwrap_or(&BUILTIN_RULES[1]);
        let target_pid = pid.unwrap_or(0);
        self.execute_containment(
            rule,
            target_pid,
            "decoy-monitor",
            &format!("Canary decoy file tampered: {}", decoy_path),
        )
    }

    fn execute_containment(
        &self,
        rule: &DetectionRule,
        pid: u32,
        process_name: &str,
        evidence: &str,
    ) -> SecurityAlert {
        let mut action_taken = String::new();
        let mut containment_success = true;

        warn!(
            "[AUTONOMOUS DETECT] Rule [{}] {} triggered by PID {} ({}) - Severity: {:?}",
            rule.id, rule.name, pid, process_name, rule.severity
        );

        let current_pid = std::process::id();

        match rule.action {
            ContainmentAction::AlertOnly => {
                action_taken = "Audit Alert Logged".to_string();
            }
            ContainmentAction::KillProcess => {
                if pid > 4 && pid != current_pid {
                    match terminate_process_by_pid(pid) {
                        Ok(_) => {
                            action_taken = format!("Sub-ms Process PID {} terminated", pid);
                            info!("[AUTONOMOUS CONTAINMENT] {}", action_taken);
                        }
                        Err(e) => {
                            action_taken = format!("Failed to terminate PID {}: {}", pid, e);
                            error!("[AUTONOMOUS ERROR] {}", action_taken);
                            containment_success = false;
                        }
                    }
                } else if pid == current_pid {
                    action_taken = "Self-termination prevented by defensive policy".to_string();
                }
            }
            ContainmentAction::KillProcessAndIsolate => {
                let mut actions = Vec::new();
                if pid > 4 && pid != current_pid {
                    match terminate_process_by_pid(pid) {
                        Ok(_) => actions.push(format!("PID {} killed", pid)),
                        Err(e) => {
                            actions.push(format!("PID kill failed ({})", e));
                            containment_success = false;
                        }
                    }
                } else if pid == current_pid {
                    actions.push("Self-kill skipped".to_string());
                }
                match isolate_host(&self.server_ip) {
                    Ok(_) => actions.push("Host network quarantined via Windows Firewall".to_string()),
                    Err(e) => {
                        actions.push(format!("Host isolation failed ({})", e));
                        containment_success = false;
                    }
                }
                action_taken = actions.join("; ");
                info!("[AUTONOMOUS CONTAINMENT] {}", action_taken);
            }
            ContainmentAction::KillProcessAndLockWorkstation => {
                let mut actions = Vec::new();
                if pid > 4 && pid != current_pid {
                    let _ = terminate_process_by_pid(pid);
                    actions.push(format!("PID {} killed", pid));
                } else if pid == current_pid {
                    actions.push("Self-kill skipped".to_string());
                }
                let _ = lock_workstation();
                actions.push("Workstation locked".to_string());
                action_taken = actions.join("; ");
                info!("[AUTONOMOUS CONTAINMENT] {}", action_taken);
            }
        }

        let alert = SecurityAlert {
            alert_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            rule_id: rule.id.to_string(),
            rule_name: rule.name.to_string(),
            mitre_technique: rule.mitre_technique.to_string(),
            severity: rule.severity,
            offending_pid: pid,
            process_name: process_name.to_string(),
            evidence: evidence.to_string(),
            action_taken,
            containment_success,
        };

        if let Ok(mut hist) = self.alert_history.lock() {
            // Keep recent 100 alerts in memory
            if hist.len() > 100 {
                hist.remove(0);
            }
            hist.push(alert.clone());
        }

        alert
    }

    pub fn drain_alerts(&self) -> Vec<SecurityAlert> {
        if let Ok(mut hist) = self.alert_history.lock() {
            std::mem::take(&mut *hist)
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomous_evaluation_and_rules() {
        let engine = AutonomousEngine::new("127.0.0.1".to_string());

        // 1. Test Benign Command -> No Alert
        let benign = EtwProcessStart {
            pid: 1234,
            parent_pid: 1000,
            image_name: "notepad.exe".to_string(),
            command_line: "notepad.exe C:\\Users\\user\\notes.txt".to_string(),
            user_sid: None,
            timestamp: Utc::now(),
        };
        assert!(engine.evaluate_process_start(&benign).is_none());

        // 2. Test Ransomware VSS Deletion -> IOA-001 Match
        let vss_threat = EtwProcessStart {
            pid: 9999, // non-existent PID, containment gracefully handles invalid PID
            parent_pid: 1000,
            image_name: "vssadmin.exe".to_string(),
            command_line: "vssadmin.exe delete shadows /all /quiet".to_string(),
            user_sid: None,
            timestamp: Utc::now(),
        };
        let alert1 = engine.evaluate_process_start(&vss_threat);
        assert!(alert1.is_some());
        let a1 = alert1.unwrap();
        assert_eq!(a1.rule_id, "IOA-001");
        assert_eq!(a1.severity, RuleSeverity::Critical);

        // 3. Test Mimikatz In-Memory Credential Theft -> IOA-004 Match
        let mimi_threat = EtwProcessStart {
            pid: 9998,
            parent_pid: 1000,
            image_name: "powershell.exe".to_string(),
            command_line: "powershell.exe -ep bypass -c Invoke-Mimikatz".to_string(),
            user_sid: None,
            timestamp: Utc::now(),
        };
        let alert2 = engine.evaluate_process_start(&mimi_threat);
        assert!(alert2.is_some());
        let a2 = alert2.unwrap();
        assert_eq!(a2.rule_id, "IOA-004");
        assert_eq!(a2.severity, RuleSeverity::High);

        // 4. Test Memory Threat -> IOA-003 Match
        let mem_threat = MemoryThreat {
            pid: 9997,
            process_name: "svchost.exe".to_string(),
            base_address: "0x2A0000".to_string(),
            region_size: 65536,
            threat_type: "Reflective PE Injection (Unbacked MZ Header)".to_string(),
            details: "Private executable memory region contains portable executable MZ header".to_string(),
        };
        let alert3 = engine.evaluate_memory_threat(&mem_threat);
        assert_eq!(alert3.rule_id, "IOA-003");
        assert_eq!(alert3.severity, RuleSeverity::High);

        // 5. Verify Alert History Drain
        let drained = engine.drain_alerts();
        assert_eq!(drained.len(), 3);
        assert!(engine.drain_alerts().is_empty());
    }
}

