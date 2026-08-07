use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;

use crate::tshark;

pub struct AppState {
    pub tshark_path: Mutex<Option<PathBuf>>,
}

#[tauri::command]
pub fn locate_tshark(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Option<String> {
    tshark::locate(&app, &state)
}

#[tauri::command]
pub fn set_tshark_path(path: String, state: tauri::State<'_, AppState>) {
    *state.tshark_path.lock().unwrap() = Some(PathBuf::from(path));
}

#[derive(Serialize)]
pub struct CaptureOutput {
    pub json: String,
    pub size: u64,
    pub path: String, // 供后续 fetch_hex 使用(临时文件场景下为写入后的真实路径)
}

#[tauri::command]
pub fn open_capture(
    path: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<CaptureOutput, String> {
    let bin = tshark::resolve(&app, &state).ok_or("tshark not found: set its path in settings")?;
    let json = tshark::run_capture(&bin, &path)?;
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(CaptureOutput { json, size, path })
}

#[tauri::command]
pub fn open_capture_data(
    file_name: String,
    base64_data: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<CaptureOutput, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let bytes = B64.decode(base64_data).map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir();
    let tmp = dir.join(&file_name);
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    open_capture(tmp.to_string_lossy().into_owned(), app, state)
}

#[tauri::command]
pub fn fetch_hex(
    path: String,
    frame_number: u32,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let bin = tshark::resolve(&app, &state).ok_or("tshark not found: set its path in settings")?;
    tshark::run_hex(&bin, &path, frame_number)
}

#[tauri::command]
pub fn save_png(default_name: String, base64_data: String) -> Result<Option<String>, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
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
