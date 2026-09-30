use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentAction {
    AlertOnly,
    KillProcess,
    KillProcessAndIsolate,
    KillProcessAndLockWorkstation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mitre_technique: &'static str,
    pub severity: RuleSeverity,
    pub action: ContainmentAction,
}

pub static BUILTIN_RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "IOA-001",
        name: "Ransomware Shadow Copy Deletion",
        description: "Process attempted to delete Volume Shadow Copies to prevent system recovery",
        mitre_technique: "T1490 (Inhibit System Recovery)",
        severity: RuleSeverity::Critical,
        action: ContainmentAction::KillProcessAndIsolate,
    },
    DetectionRule {
        id: "IOA-002",
        name: "Canary / Decoy File Tampering",
        description: "Canary decoy honeypot file accessed or modified by unauthorized process",
        mitre_technique: "T1486 (Data Encrypted for Impact)",
        severity: RuleSeverity::Critical,
        action: ContainmentAction::KillProcessAndIsolate,
    },
    DetectionRule {
        id: "IOA-003",
        name: "Reflective PE Memory Injection",
        description: "Unbacked private executable memory containing portable executable MZ header",
        mitre_technique: "T1055.001 (Reflective Code Loading)",
        severity: RuleSeverity::High,
        action: ContainmentAction::KillProcess,
    },
    DetectionRule {
        id: "IOA-004",
        name: "In-Memory Credential Dumping",
        description: "Script or binary executed Mimikatz / Sekurlsa credential extraction routine",
        mitre_technique: "T1003.001 (OS Credential Dumping: LSASS)",
        severity: RuleSeverity::High,
        action: ContainmentAction::KillProcess,
    },
    DetectionRule {
        id: "IOA-005",
        name: "Dynamic Web Cradle Execution",
        description: "Dynamic download and immediate in-memory evaluation (IEX + WebDownload)",
        mitre_technique: "T1059.001 (Command and Scripting: PowerShell)",
        severity: RuleSeverity::High,
        action: ContainmentAction::KillProcess,
    },
    DetectionRule {
        id: "IOA-006",
        name: "Covert Tunneling Backdoor",
        description: "Reverse tunnel proxy detected (ngrok, chisel, frpc, localtunnel)",
        mitre_technique: "T1572 (Protocol Tunneling)",
        severity: RuleSeverity::Medium,
        action: ContainmentAction::KillProcess,
    },
];

pub fn get_rule_by_id(id: &str) -> Option<&'static DetectionRule> {
    BUILTIN_RULES.iter().find(|r| r.id == id)
}

pub fn evaluate_command_line(cmd: &str) -> Option<&'static DetectionRule> {
    let lower = cmd.to_lowercase();

    // Check IOA-001: Shadow copy deletion & recovery inhibition
    let is_vss_kill = (lower.contains("vssadmin") && lower.contains("delete") && lower.contains("shadow"))
        || (lower.contains("wmic") && lower.contains("shadowcopy") && lower.contains("delete"))
        || (lower.contains("win32_shadowcopy") && (lower.contains("delete") || lower.contains("remove")))
        || (lower.contains("wbadmin") && lower.contains("delete") && (lower.contains("catalog") || lower.contains("systemstatebackup")))
        || (lower.contains("resize shadowstorage") && lower.contains("/maxsize="))
        || (lower.contains("bcdedit") && lower.contains("bootstatuspolicy") && lower.contains("ignoreallfailures"));
    if is_vss_kill {
        return Some(&BUILTIN_RULES[0]);
    }

    // Check IOA-004: Credential dumping (LSASS extraction)
    let is_cred_dump = lower.contains("invoke-mimikatz")
        || lower.contains("sekurlsa::logonpasswords")
        || lower.contains("lsadump::")
        || (lower.contains("comsvcs") && lower.contains("minidump"))
        || (lower.contains("procdump") && lower.contains("lsass"))
        || lower.contains("nanodump");
    if is_cred_dump {
        return Some(&BUILTIN_RULES[3]);
    }

    // Check IOA-005: Web cradle
    let has_download = lower.contains("downloadstring") || lower.contains("downloadfile") || lower.contains("iwr ");
    let has_iex = lower.contains("iex ") || lower.contains("invoke-expression") || lower.contains("iex(");
    if has_download && has_iex {
        return Some(&BUILTIN_RULES[4]);
    }

    // Check IOA-006: Tunneling
    let tunneling_binaries = ["ngrok", "chisel.exe", "frpc.exe", "localtunnel"];
    if tunneling_binaries.iter().any(|&b| lower.contains(b)) {
        return Some(&BUILTIN_RULES[5]);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expanded_ioa_detections() {
        assert_eq!(
            evaluate_command_line("powershell.exe -Command (gwmi Win32_ShadowCopy).Delete()").unwrap().id,
            "IOA-001"
        );
        assert_eq!(
            evaluate_command_line("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full").unwrap().id,
            "IOA-004"
        );
        assert_eq!(
            evaluate_command_line("procdump.exe -ma lsass.exe lsass.dmp").unwrap().id,
            "IOA-004"
        );
        assert_eq!(
            evaluate_command_line("wbadmin delete catalog -quiet").unwrap().id,
            "IOA-001"
        );
    }
}
