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

/// 解析结果缓存:打包后的 GUI 无控制台,每次 spawn 子进程都会闪现 cmd 窗口并带来延迟,
/// 因此把解析结果缓存下来,仅当路径失效或用户重新设置时再解析。
pub fn resolve_cached(app: &tauri::AppHandle, state: &AppState) -> Option<PathBuf> {
    let mut cache = state.resolved_path.lock().unwrap();
    if let Some(p) = cache.as_ref() {
        if p.exists() {
            return Some(p.clone());
        }
    }
    let resolved = resolve(app, state);
    if let Some(p) = resolved.as_ref() {
        *cache = Some(p.clone());
    }
    resolved
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
    if file.starts_with('-') {
        return Err("invalid capture path".into()); // 防 `-` 前缀选项混淆/`-r -` 卡读 stdin
    }
    run(bin, &["-r", file, "-T", "json", "-J", "frame eth ip ipv6 tcp udp http dns tls"])
}

pub fn run_hex(bin: &Path, file: &str, number: u32) -> Result<String, String> {
    if file.starts_with('-') {
        return Err("invalid capture path".into());
    }
    let filter = format!("frame.number=={number}");
    run(bin, &["-r", file, "-Y", &filter, "-x"])
}

#[cfg(windows)]
fn hide_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000; // 不创建新控制台窗口
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_cmd: &mut Command) {}

fn run(bin: &Path, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    hide_console(&mut cmd);
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("failed to run tshark: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn locate(app: &tauri::AppHandle, state: &AppState) -> Option<String> {
    resolve_cached(app, state).map(|p| p.to_string_lossy().into_owned())
}

fn find_in_path() -> Option<String> {
    let which = if cfg!(windows) { "where" } else { "which" };
    let mut cmd = Command::new(which);
    hide_console(&mut cmd);
    let out = cmd.arg("tshark").output().ok()?;
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
    fn run_rejects_dash_prefixed_capture_path() {
        // `-` 前缀会被 tshark 当作选项,`-r -` 会卡读 stdin
        assert!(run_capture(Path::new("/usr/bin/tshark"), "-Y").is_err());
        assert!(run_hex(Path::new("/usr/bin/tshark"), "-r", 1).is_err());
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
