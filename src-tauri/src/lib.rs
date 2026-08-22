pub mod commands;
pub mod tshark;

use std::sync::Arc;

use tauri::Manager;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(AppState {
            tshark_path: Default::default(),
            resolved_path: Default::default(),
            temp_files: Default::default(),
        }))
        .invoke_handler(tauri::generate_handler![
            commands::locate_tshark,
            commands::set_tshark_path,
            commands::open_capture,
            commands::open_capture_data,
            commands::fetch_hex,
            commands::tshark_version,
            commands::save_png,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|app, event| {
        // 退出时清理 open_capture_data 写入的临时抓包文件,避免敏感数据残留 %TEMP%
        if let tauri::RunEvent::Exit = event {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                let files = state.temp_files.lock().unwrap_or_else(|e| e.into_inner());
                for p in files.iter() {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    });
}
