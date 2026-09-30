use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Extracts clean IP or hostname from a URL or socket address (e.g. "https://192.168.1.5:8080/api" -> "192.168.1.5")
pub fn extract_ip_or_host(input: &str) -> &str {
    let mut s = input;
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    }
    if let Some(pos) = s.find('/') {
        s = &s[..pos];
    }
    if let Some(pos) = s.find(':') {
        s = &s[..pos];
    }
    if s.is_empty() {
        "127.0.0.1"
    } else {
        s
    }
}

/// Isolates the endpoint network by setting default-drop outbound policy and allowing only InsiEDR server traffic.
pub fn isolate_host(server_target: &str) -> Result<(), String> {
    let target_ip = extract_ip_or_host(server_target);

    // netsh advfirewall strictly requires numerical IP or subnet; resolve hostnames/localhost
    let resolved_ip = if target_ip.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_string()
    } else if target_ip.parse::<std::net::IpAddr>().is_ok() {
        target_ip.to_string()
    } else {
        use std::net::ToSocketAddrs;
        format!("{target_ip}:443")
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|sa| sa.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    };

    // 1. Delete prior isolation rule if present
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=InsiEDR_Isolation_AllowServer"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // 2. Add Allow Rule for InsiEDR C2 server
    let out_allow = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            "name=InsiEDR_Isolation_AllowServer",
            "dir=out", "action=allow", "enable=yes",
            &format!("remoteip={resolved_ip}")
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to add allow-server rule: {e}"))?;

    if !out_allow.status.success() {
        return Err(String::from_utf8_lossy(&out_allow.stderr).to_string());
    }

    // 3. Set outbound policy to Block (default drop) across all firewall profiles
    let out_policy = Command::new("netsh")
        .args(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to set isolation firewall policy: {e}"))?;

    if !out_policy.status.success() {
        return Err(String::from_utf8_lossy(&out_policy.stderr).to_string());
    }

    Ok(())
}

/// Restores normal network connectivity by removing isolation rules and restoring default outbound policy.
pub fn unisolate_host() -> Result<(), String> {
    // 1. Restore standard Windows firewall policy (block inbound, allow outbound)
    let _ = Command::new("netsh")
        .args(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // 2. Remove temporary isolation rules
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=InsiEDR_Isolation_AllowServer"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=InsiEDR_Isolation_BlockAll"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip_or_host() {
        assert_eq!(extract_ip_or_host("http://192.168.1.50:8080/api"), "192.168.1.50");
        assert_eq!(extract_ip_or_host("https://edr.corp.internal:443"), "edr.corp.internal");
        assert_eq!(extract_ip_or_host("10.0.0.1"), "10.0.0.1");
        assert_eq!(extract_ip_or_host("127.0.0.1:9000"), "127.0.0.1");
        assert_eq!(extract_ip_or_host(""), "127.0.0.1");
    }
}
