use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::tshark;

/// 状态以 Arc<AppState> 托管:async 命令可把 Arc 克隆进 spawn_blocking 闭包共享同一组锁
pub struct AppState {
    pub tshark_path: Mutex<Option<PathBuf>>,
    /// resolve 结果缓存,避免每次调用都重新 spawn `where`/`tshark`(见 tshark::resolve_cached)
    pub resolved_path: Mutex<Option<PathBuf>>,
}

/// 命令全部 async + spawn_blocking:Tauri 同步命令跑在主线程,
/// 而 tshark 解析(≤128MB JSON)/base64 解码(≤192MB)可能耗时数秒到数十秒,
/// 同步执行会整窗冻结;阻塞段放到 blocking 线程池后 UI 保持响应。
#[tauri::command]
pub async fn locate_tshark(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    let state = state.inner().clone();
    let found = tauri::async_runtime::spawn_blocking(move || tshark::locate(&app, &state))
        .await
        .map_err(|e| format!("locate_tshark task failed: {e}"))?;
    Ok(found)
}

#[tauri::command]
pub fn set_tshark_path(path: String, state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    let p = validate_tshark_path(&path)?;
    *state.tshark_path.lock().unwrap() = Some(p);
    *state.resolved_path.lock().unwrap() = None; // 使缓存失效
    Ok(())
}

#[derive(Serialize)]
pub struct CaptureOutput {
    pub json: String,
    pub size: u64,
    pub path: String, // 供后续 fetch_hex 使用(临时文件场景下为写入后的真实路径)
}

#[tauri::command]
pub async fn open_capture(
    path: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<CaptureOutput, String> {
    let app = app.clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || open_capture_blocking(&path, &app, &state))
        .await
        .map_err(|e| format!("open_capture task failed: {e}"))?
}

fn open_capture_blocking(
    path: &str,
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<CaptureOutput, String> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size > MAX_CAPTURE_FILE {
        return Err("capture file too large".into());
    }
    let bin = tshark::resolve_cached(app, state).ok_or("tshark not found: set its path in settings")?;
    let json = tshark::run_capture(&bin, path)?;
    Ok(CaptureOutput {
        json,
        size,
        path: path.to_string(),
    })
}

/// 捕获数据(base64)解码上限:约 256MB,防止超大打爆内存
const MAX_CAPTURE_BASE64: usize = 256 * 1024 * 1024;
/// PNG(base64)上限:约 64MB,时序图导出远小于此
const MAX_PNG_BASE64: usize = 64 * 1024 * 1024;
/// 输入抓包文件上限:过大直接拒绝,避免 tshark 产出巨型 JSON
const MAX_CAPTURE_FILE: u64 = 512 * 1024 * 1024;

/// 校验 tshark 路径:须为绝对路径、文件存在、文件名含 tshark。
/// 缩小「set_tshark_path + open_capture = 任意二进制执行」的能力面。
fn validate_tshark_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::PathBuf::from(path);
    if !p.is_absolute() {
        return Err("tshark path must be absolute".into());
    }
    if !p.is_file() {
        return Err("tshark path does not exist".into());
    }
    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    if !name.contains("tshark") {
        return Err("path must point to a tshark executable".into());
    }
    Ok(p)
}

/// 清洗临时文件名:只取 basename,拒绝空名/隐藏文件/`..`,防路径穿越写到临时目录之外
fn sanitize_capture_name(file_name: &str) -> Option<String> {
    std::path::Path::new(file_name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && !n.contains("..") && !n.starts_with('.'))
}

#[tauri::command]
pub async fn open_capture_data(
    file_name: String,
    base64_data: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<CaptureOutput, String> {
    let app = app.clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        if base64_data.len() > MAX_CAPTURE_BASE64 {
            return Err("capture data too large".into());
        }
        let bytes = B64.decode(base64_data).map_err(|e| e.to_string())?;
        let name = sanitize_capture_name(&file_name).ok_or("invalid capture file name")?;
        let dir = std::env::temp_dir();
        let tmp = dir.join(&name);
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        open_capture_blocking(&tmp.to_string_lossy().into_owned(), &app, &state)
    })
    .await
    .map_err(|e| format!("open_capture_data task failed: {e}"))?
}

#[tauri::command]
pub async fn fetch_hex(
    path: String,
    frame_number: u32,
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let app = app.clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let bin = tshark::resolve_cached(&app, &state).ok_or("tshark not found: set its path in settings")?;
        tshark::run_hex(&bin, &path, frame_number)
    })
    .await
    .map_err(|e| format!("fetch_hex task failed: {e}"))?
}

#[tauri::command]
pub fn save_png(default_name: String, base64_data: String) -> Result<Option<String>, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    if base64_data.len() > MAX_PNG_BASE64 {
        return Err("png data too large".into());
    }
    let bytes = B64.decode(base64_data).map_err(|e| e.to_string())?;
    let path = rfd::FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("PNG", &["png"])
        .save_file();
    if let Some(p) = path {
        std::fs::write(&p, &bytes).map_err(|e| e.to_string())?;
        Ok(Some(p.to_string_lossy().into_owned()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_capture_name_neutralizes_traversal() {
        assert_eq!(sanitize_capture_name("http.pcapng").as_deref(), Some("http.pcapng"));
        // 目录穿越被中和为纯 basename,只可能写到 temp_dir 内
        assert_eq!(sanitize_capture_name("..\\..\\x.bat").as_deref(), Some("x.bat"));
        assert_eq!(sanitize_capture_name("a/b.pcapng").as_deref(), Some("b.pcapng"));
        assert_eq!(sanitize_capture_name(".hidden"), None); // 隐藏文件
        assert_eq!(sanitize_capture_name("a..b.pcap"), None); // 名字含 ".."
        assert_eq!(sanitize_capture_name(""), None);
    }

    #[test]
    fn validate_tshark_path_requires_real_tshark_file() {
        // 相对路径拒绝
        assert!(validate_tshark_path("tshark.exe").is_err());
        // 不存在的绝对路径拒绝
        assert!(validate_tshark_path("C:\\nonexistent\\tshark.exe").is_err());
        // 存在的文件但文件名不含 tshark → 拒绝(能力面收窄)
        let dir = std::env::temp_dir();
        let fake = dir.join("pui-evil.exe");
        std::fs::write(&fake, b"x").unwrap();
        let fake_abs = std::fs::canonicalize(&fake).unwrap().to_string_lossy().into_owned();
        assert!(validate_tshark_path(&fake_abs).is_err());
        // 文件名含 tshark 的真实文件 → 通过
        let tshark = dir.join("pui-tshark-validation.exe");
        std::fs::write(&tshark, b"x").unwrap();
        let tshark_abs = std::fs::canonicalize(&tshark).unwrap().to_string_lossy().into_owned();
        assert!(validate_tshark_path(&tshark_abs).is_ok());
        let _ = std::fs::remove_file(&fake);
        let _ = std::fs::remove_file(&tshark);
    }
}
