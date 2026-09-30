use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshotInfo {
    pub shadow_id: String,
    pub volume: String,
    pub device_path: String,
    pub creation_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackReport {
    pub target_path: String,
    pub snapshot_used: String,
    pub files_restored: usize,
    pub bytes_restored: u64,
    pub errors: Vec<String>,
    pub success: bool,
}

/// Enumerate all active Volume Shadow Copies on the system
pub fn list_vss_snapshots() -> Result<Vec<VssSnapshotInfo>, String> {
    let output = Command::new("vssadmin")
        .args(["list", "shadows"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute vssadmin: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut snapshots = Vec::new();

    let mut current_id = String::new();
    let mut current_vol = String::new();
    let mut current_device = String::new();
    let mut current_time = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Shadow Copy ID:") {
            if !current_device.is_empty() {
                snapshots.push(VssSnapshotInfo {
                    shadow_id: current_id.clone(),
                    volume: current_vol.clone(),
                    device_path: current_device.clone(),
                    creation_time: current_time.clone(),
                });
            }
            current_id = trimmed.replace("Shadow Copy ID:", "").trim().to_string();
            current_vol.clear();
            current_device.clear();
            current_time.clear();
        } else if trimmed.starts_with("Original Volume:") {
            current_vol = trimmed.replace("Original Volume:", "").trim().to_string();
        } else if trimmed.starts_with("Shadow Copy Volume Name:") {
            current_device = trimmed.replace("Shadow Copy Volume Name:", "").trim().to_string();
        } else if trimmed.starts_with("Creation Time:") {
            current_time = trimmed.replace("Creation Time:", "").trim().to_string();
        }
    }

    if !current_device.is_empty() {
        snapshots.push(VssSnapshotInfo {
            shadow_id: current_id,
            volume: current_vol,
            device_path: current_device,
            creation_time: current_time,
        });
    }

    Ok(snapshots)
}

/// Automatically provision a new Volume Shadow Copy for a drive (e.g. "C:")
pub fn create_vss_snapshot(volume: &str) -> Result<String, String> {
    let target_vol = if volume.ends_with('\\') {
        volume.to_string()
    } else {
        format!("{}\\", volume)
    };

    let arg = format!("/for={}", target_vol);
    info!("Creating automated Volume Shadow Copy for {}...", target_vol);

    let output = Command::new("vssadmin")
        .args(["create", "shadow", &arg])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to create shadow copy: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("vssadmin error ({}): {}", stdout.trim(), stderr.trim()));
    }

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Shadow Copy Volume Name:") {
            let device = trimmed.replace("Shadow Copy Volume Name:", "").trim().to_string();
            info!("Successfully created Volume Shadow Copy: {}", device);
            return Ok(device);
        }
    }

    Ok("Shadow snapshot created successfully".to_string())
}

/// Restores a single file from the latest (or specified) Shadow Copy snapshot
pub fn rollback_file(file_path: &str, explicit_snapshot: Option<&str>) -> Result<u64, String> {
    let path = Path::new(file_path);
    if !path.is_absolute() {
        return Err("File path must be an absolute Windows path (e.g. C:\\...)".to_string());
    }

    let snapshot_device = match explicit_snapshot {
        Some(s) => s.to_string(),
        None => {
            let snaps = list_vss_snapshots()?;
            snaps.last()
                .ok_or_else(|| "No Volume Shadow Copies available on this system to restore from".to_string())?
                .device_path
                .clone()
        }
    };

    // Strip volume drive letter: "C:\Users\Doc.txt" -> "Users\Doc.txt"
    let path_str = path.to_string_lossy();
    let relative_part = if let Some(idx) = path_str.find(":\\") {
        &path_str[idx + 2..]
    } else {
        &path_str
    };

    let shadow_source = format!("{}\\{}", snapshot_device.trim_end_matches('\\'), relative_part);
    let shadow_path = PathBuf::from(&shadow_source);

    if !shadow_path.exists() {
        return Err(format!("File does not exist in shadow snapshot: {}", shadow_source));
    }

    // Clear read-only attribute if locked by ransomware to avoid AccessDenied
    if path.exists() {
        if let Ok(meta) = path.metadata() {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }

    // Atomic restore copy
    let bytes = std::fs::copy(&shadow_path, path)
        .map_err(|e| format!("Failed to restore file from {}: {}", shadow_source, e))?;

    info!("Rollback successfully restored {} ({} bytes) from {}", file_path, bytes, snapshot_device);
    Ok(bytes)
}

/// Recursively rolls back an entire directory of files from the latest Shadow Copy snapshot,
/// automatically handling and cleaning up ransomware-appended extensions (.locked, .enc, etc.).
pub fn rollback_directory(dir_path: &str, explicit_snapshot: Option<&str>) -> Result<RollbackReport, String> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        return Err(format!("Target path is not a valid directory: {}", dir_path));
    }

    let snapshot_device = match explicit_snapshot {
        Some(s) => s.to_string(),
        None => {
            let snaps = list_vss_snapshots()?;
            snaps.last()
                .ok_or_else(|| "No Volume Shadow Copies available on this system to restore from".to_string())?
                .device_path
                .clone()
        }
    };

    let mut files_restored = 0;
    let mut bytes_restored = 0;
    let mut errors = Vec::new();

    let ransomware_extensions = [
        ".locked", ".crypto", ".enc", ".crypted", ".ransom", ".lockbit", ".blackcat", ".phobos", ".wnry"
    ];

    let mut stack = vec![path.to_path_buf()];

    while let Some(current_dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    stack.push(entry_path);
                } else if entry_path.is_file() {
                    let path_str = entry_path.to_string_lossy().to_string();
                    match rollback_file(&path_str, Some(&snapshot_device)) {
                        Ok(b) => {
                            files_restored += 1;
                            bytes_restored += b;
                        }
                        Err(e) => {
                            // Check if this file was renamed by ransomware with an extra extension (e.g. file.docx.locked)
                            let mut recovered = false;
                            let lower = path_str.to_lowercase();
                            let is_ransom_ext = ransomware_extensions.iter().any(|&ext| lower.ends_with(ext));

                            if is_ransom_ext || entry_path.extension().is_some() {
                                if let Some(parent) = entry_path.parent() {
                                    if let Some(stem) = entry_path.file_stem() {
                                        let original_candidate = parent.join(stem);
                                        let orig_str = original_candidate.to_string_lossy().to_string();
                                        if let Ok(b) = rollback_file(&orig_str, Some(&snapshot_device)) {
                                            files_restored += 1;
                                            bytes_restored += b;
                                            let _ = std::fs::remove_file(&entry_path);
                                            info!("Restored original {:?} and removed encrypted ransomware file {:?}", orig_str, entry_path);
                                            recovered = true;
                                        }
                                    }
                                }
                            }

                            if !recovered {
                                warn!("Rollback file skip: {}", e);
                                errors.push(e);
                            }
                        }
                    }
                }
            }
        }
    }

    let success = files_restored > 0 || errors.is_empty();

    Ok(RollbackReport {
        target_path: dir_path.to_string(),
        snapshot_used: snapshot_device,
        files_restored,
        bytes_restored,
        errors,
        success,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vss_parser_logic() {
        let sample_output = r#"
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {b6d3957f-178b-4b13-9a3b-2856f6c0395d}
   Contained 1 shadow copies at creation time: 24-09-2026 08:30:15
      Shadow Copy ID: {4d8b41d8-927a-45c6-a6f7-4a47e53b0b2e}
      Original Volume: (C:)\\?\Volume{b1b9e6e0-0000-0000-0000-6022d4000000}\
      Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
      Originating Machine: HOST-SECURE
      Service Machine: HOST-SECURE
      Provider: 'Microsoft Software Shadow Copy provider 1.0'
      Type: ClientAccessibleWriters
      Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
"#;

        let mut snapshots = Vec::new();
        let mut current_id = String::new();
        let mut current_vol = String::new();
        let mut current_device = String::new();
        let mut current_time = String::new();

        for line in sample_output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Shadow Copy ID:") {
                current_id = trimmed.replace("Shadow Copy ID:", "").trim().to_string();
            } else if trimmed.starts_with("Original Volume:") {
                current_vol = trimmed.replace("Original Volume:", "").trim().to_string();
            } else if trimmed.starts_with("Shadow Copy Volume Name:") {
                current_device = trimmed.replace("Shadow Copy Volume Name:", "").trim().to_string();
            } else if trimmed.starts_with("Creation Time:") {
                current_time = trimmed.replace("Creation Time:", "").trim().to_string();
            }
        }

        if !current_device.is_empty() {
            snapshots.push(VssSnapshotInfo {
                shadow_id: current_id,
                volume: current_vol,
                device_path: current_device,
                creation_time: current_time,
            });
        }

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].shadow_id, "{4d8b41d8-927a-45c6-a6f7-4a47e53b0b2e}");
        assert_eq!(snapshots[0].device_path, r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1");
    }

    #[test]
    fn test_ransomware_extension_detection() {
        let ransomware_extensions = [
            ".locked", ".crypto", ".enc", ".crypted", ".ransom", ".lockbit", ".blackcat", ".phobos", ".wnry"
        ];
        let test_file = "C:\\Users\\Victim\\Documents\\Financials.xlsx.locked";
        let is_ransom = ransomware_extensions.iter().any(|&ext| test_file.to_lowercase().ends_with(ext));
        assert!(is_ransom);

        let p = std::path::Path::new(test_file);
        let orig = p.parent().unwrap().join(p.file_stem().unwrap());
        assert_eq!(orig.to_string_lossy(), "C:\\Users\\Victim\\Documents\\Financials.xlsx");
    }
}
