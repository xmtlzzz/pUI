use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::tshark;

/// 状态以 Arc<AppState> 托管:async 命令可把 Arc 克隆进 spawn_blocking 闭包共享同一组锁
pub struct AppState {
    pub tshark_path: Mutex<Option<PathBuf>>,
    /// resolve 结果缓存,避免每次调用都重新 spawn `where`/`tshark`(见 tshark::resolve_cached)
    pub resolved_path: Mutex<Option<PathBuf>>,
    /// open_capture_data 写入的临时抓包文件,应用退出时统一清理(敏感数据不残留 %TEMP%)
    pub temp_files: Mutex<Vec<PathBuf>>,
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
    *state.tshark_path.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
    *state.resolved_path.lock().unwrap_or_else(|e| e.into_inner()) = None; // 使缓存失效
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

/// 校验捕获路径为常规文件并返回大小:目录/命名管道/FIFO 直达 tshark,
/// 会让 `-r` 读 FIFO 永不 EOF(无超时下整窗挂死),必须前置拦截
fn check_capture_path(path: &str) -> Result<u64, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("capture path is not a regular file".into());
    }
    let size = meta.len();
    if size > MAX_CAPTURE_FILE {
        return Err("capture file too large".into());
    }
    Ok(size)
}

fn open_capture_blocking(
    path: &str,
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<CaptureOutput, String> {
    let size = check_capture_path(path)?;
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
/// 文本导出(时序叙述 Markdown)上限:约 2MB,远超正常会话
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
/// PNG(base64)上限:约 64MB,时序图导出远小于此
const MAX_PNG_BASE64: usize = 64 * 1024 * 1024;
/// 输入抓包文件上限:过大直接拒绝,避免 tshark 产出巨型 JSON
const MAX_CAPTURE_FILE: u64 = 512 * 1024 * 1024;

/// 校验 tshark 路径:须为绝对路径、真实常规文件(拒绝符号链接冒名)、文件名含 tshark。
/// 缩小「set_tshark_path + open_capture = 任意二进制执行」的能力面。
fn validate_tshark_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::PathBuf::from(path);
    if !p.is_absolute() {
        return Err("tshark path must be absolute".into());
    }
    let meta = std::fs::symlink_metadata(&p).map_err(|_| "tshark path does not exist".to_string())?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err("tshark path must be a real file, not a symbolic link".into());
    }
    #[cfg(windows)]
    {
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("exe") {
            // .bat/.cmd 等可由 CreateProcess 执行,仅文件名含 tshark 不足以拦截
            return Err("tshark path must be a .exe executable on Windows".into());
        }
    }
    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    if !name.contains("tshark") {
        return Err("path must point to a tshark executable".into());
    }
    // 规范化为真实路径,收窄「校验通过后被替换」的 TOCTOU 面
    Ok(std::fs::canonicalize(&p).unwrap_or(p))
}

/// Windows 保留设备名(CON/PRN/AUX/NUL/COM1-9/LPT1-9):写进 %TEMP%\NUL 会静默丢数据
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 清洗临时文件名:只取 basename,拒绝空名/隐藏文件/`..`,防路径穿越写到临时目录之外;
/// Windows 上另拒绝保留设备名/NTFS 交替流(冒号)/尾随点与空格(系统归一化后别名覆盖)
fn sanitize_capture_name(file_name: &str) -> Option<String> {
    let base = std::path::Path::new(file_name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())?;
    if base.is_empty() || base.contains("..") || base.starts_with('.') {
        return None;
    }
    #[cfg(windows)]
    {
        let stem = base.split('.').next().unwrap_or("");
        if WINDOWS_RESERVED.contains(&stem.to_ascii_uppercase().as_str()) {
            return None;
        }
        if base.contains(':') {
            return None; // NTFS 交替数据流(evil.pcap:stream 会留幽灵文件)
        }
        let trimmed = base.trim_end_matches(['.', ' ', '\t']);
        if trimmed != base || base.ends_with('.') || base.ends_with(' ') {
            return None; // 尾随点/空格被 Windows 归一化,与相邻文件别名冲突
        }
    }
    Some(base)
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
        // 唯一化临时文件名:固定名会与并发打开写同一路径(读到撕裂文件),且便于退出时按注册表清理
        let token = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = std::env::temp_dir().join(format!("pui-{token}-{name}"));
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        state.temp_files.lock().unwrap_or_else(|e| e.into_inner()).push(tmp.clone());
        open_capture_blocking(&tmp.to_string_lossy().into_owned(), &app, &state)
    })
    .await
    .map_err(|e| format!("open_capture_data task failed: {e}"))?
}

#[tauri::command]
pub async fn tshark_version(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    let app = app.clone();
    let state = state.inner().clone();
    let v = tauri::async_runtime::spawn_blocking(move || -> Result<Option<String>, String> {
        let Some(bin) = tshark::resolve_cached(&app, &state) else {
            return Ok(None); // 未找到 tshark:版本位留空,界面不展示
        };
        Ok(tshark::tshark_version(&bin))
    })
    .await
    .map_err(|e| format!("tshark_version task failed: {e}"))??;
    Ok(v)
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
pub fn save_text(default_name: String, content: String) -> Result<Option<String>, String> {
    if content.len() > MAX_TEXT_BYTES {
        return Err("text too large".into());
    }
    let path = rfd::FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("Markdown", &["md"])
        .save_file();
    if let Some(p) = path {
        std::fs::write(&p, content).map_err(|e| e.to_string())?;
        Ok(Some(p.to_string_lossy().into_owned()))
    } else {
        Ok(None)
    }
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
        assert_eq!(sanitize_capture_name("a/b.pcapng").as_deref(), Some("b.pcapng"));
        assert_eq!(sanitize_capture_name(".hidden"), None); // 隐藏文件
        assert_eq!(sanitize_capture_name("a..b.pcap"), None); // 名字含 ".."
        assert_eq!(sanitize_capture_name(""), None);
        if cfg!(windows) {
            // Windows:反斜杠是分隔符,目录穿越被中和为纯 basename(只能写到 temp_dir 内)
            assert_eq!(sanitize_capture_name("..\\..\\x.bat").as_deref(), Some("x.bat"));
        } else {
            // Unix:反斜杠不是分隔符,整体含 ".." 被拒;正斜杠穿越被中和
            assert_eq!(sanitize_capture_name("..\\..\\x.bat"), None);
            assert_eq!(sanitize_capture_name("../x.bat").as_deref(), Some("x.bat"));
        }
    }

    #[test]
    #[cfg(windows)]
    fn sanitize_rejects_windows_reserved_names_and_ads() {
        // Windows 保留设备名写进 %TEMP%\NUL 会静默丢数据;ADS/尾随点会留幽灵文件或别名覆盖
        for n in ["NUL", "CON", "PRN", "AUX", "COM1", "COM9", "LPT1", "LPT9", "CON.txt"] {
            assert_eq!(sanitize_capture_name(n), None, "{n} 应被拒绝");
        }
        assert_eq!(sanitize_capture_name("evil.pcap:stream"), None); // NTFS 交替流
        assert_eq!(sanitize_capture_name("name.txt."), None); // 尾随点被 Windows 归一化
        assert_eq!(sanitize_capture_name("name.txt "), None); // 尾随空格
        assert_eq!(sanitize_capture_name("name.txt\t"), None);
    }

    #[test]
    #[cfg(windows)]
    fn validate_tshark_path_rejects_non_exe() {
        // Windows 下 CreateProcess 可执行 .bat,仅文件名含 tshark 不足以拦截
        let dir = std::env::temp_dir();
        let bat = dir.join("pui-tshark-tool.bat");
        std::fs::write(&bat, b"@echo off").unwrap();
        let bat_abs = std::fs::canonicalize(&bat).unwrap().to_string_lossy().into_owned();
        assert!(validate_tshark_path(&bat_abs).is_err());
        let _ = std::fs::remove_file(&bat);
    }

    #[test]
    #[cfg(unix)]
    fn validate_tshark_path_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir();
        let target = dir.join("pui-tshark-real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("pui-tshark-link");
        let _ = std::fs::remove_file(&link);
        symlink(&target, &link).unwrap();
        let link_abs = link.to_string_lossy().into_owned();
        assert!(validate_tshark_path(&link_abs).is_err(), "符号链接不得冒充 tshark");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn check_capture_path_rejects_directory() {
        // 目录/命名管道直达 tshark:目录尚会报错,FIFO 会让 tshark 永不 EOF 挂死
        assert!(check_capture_path(&std::env::temp_dir().to_string_lossy()).is_err());
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
