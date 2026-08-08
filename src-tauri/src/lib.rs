pub mod commands;
pub mod tshark;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            tshark_path: Default::default(),
            resolved_path: Default::default(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::locate_tshark,
            commands::set_tshark_path,
            commands::open_capture,
            commands::open_capture_data,
            commands::fetch_hex,
            commands::save_png,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
