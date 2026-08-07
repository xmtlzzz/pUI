use std::path::{Path, PathBuf};
use std::process::Command;

use tauri::Manager;

use crate::commands::AppState;

pub fn resolve(app: &tauri::AppHandle, state: &AppState) -> Option<PathBuf> {
    // ① 用户设置路径
    if let Some(p) = state.tshark_path.lock().unwrap().clone() {
        if p.exists() {
            return Some(p);
        }
    }
    // ② 随包内置资源
    if let Some(p) = bundled(app).filter(|p| p.exists()) {
        return Some(p);
    }
    // ③ 系统: PATH → 常见安装目录(Wireshark)
    find_in_path()
        .map(PathBuf::from)
        .or_else(|| find_common_install().map(PathBuf::from))
}

fn bundled(app: &tauri::AppHandle) -> Option<PathBuf> {
    let dir = app.path().resource_dir().ok()?;
    let exe = if cfg!(windows) { "tshark.exe" } else { "tshark" };
    let p = dir.join(exe);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

pub fn run_capture(bin: &Path, file: &str) -> Result<String, String> {
    run(bin, &["-r", file, "-T", "json", "-J", "frame eth ip ipv6 tcp udp http dns tls"])
}

pub fn run_hex(bin: &Path, file: &str, number: u32) -> Result<String, String> {
    let filter = format!("frame.number=={number}");
    run(bin, &["-r", file, "-Y", &filter, "-x"])
}

fn run(bin: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run tshark: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn locate(app: &tauri::AppHandle, state: &AppState) -> Option<String> {
    resolve(app, state).map(|p| p.to_string_lossy().into_owned())
}

fn find_in_path() -> Option<String> {
    let which = if cfg!(windows) { "where" } else { "which" };
    let out = Command::new(which).arg("tshark").output().ok()?;
    if out.status.success() {
        String::from_utf8_lossy(&out.stdout).lines().next().map(|s| s.to_string())
    } else {
        None
    }
}

fn first_existing(candidates: &[&str]) -> Option<String> {
    candidates.iter().find(|p| Path::new(p).exists()).map(|s| s.to_string())
}

fn find_common_install() -> Option<String> {
    let candidates: &[&str] = if cfg!(windows) {
        &[
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &["/Applications/Wireshark.app/Contents/MacOS/tshark"]
    } else {
        &["/usr/bin/tshark", "/usr/local/bin/tshark"]
    };
    first_existing(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_capture_builds_valid_args() {
        // 在无 tshark 环境下应返回 Err 而非 panic
        let out = run_capture(Path::new("/nonexistent/tshark"), "x.pcapng");
        assert!(out.is_err());
    }

    #[test]
    fn run_hex_rejects_bad_binary() {
        assert!(run_hex(Path::new("/nonexistent/tshark"), "x.pcapng", 1).is_err());
    }

    #[test]
    fn first_existing_finds_existing_file() {
        let f = std::env::temp_dir().join("pui-tshark-locate-test.exe");
        std::fs::write(&f, b"x").unwrap();
        let abs = std::fs::canonicalize(&f).unwrap().to_string_lossy().into_owned();
        assert_eq!(first_existing(&[&abs]).as_deref(), Some(abs.as_str()));
        assert_eq!(first_existing(&["/nonexistent/a.exe", "/nonexistent/b"]), None);
        std::fs::remove_file(&f).unwrap();
    }
}
