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
        .setup(|app| {
            // 窗口默认隐藏(visible:false),前端 React 首帧后主动 show()——
            // 消除 WebView2 初始化期间的启动白屏。此处兜底:JS 万一没跑起来,
            // 2.5s 后强制显示,窗口永不消失(宁白屏勿无响应)
            let window = app.get_webview_window("main");
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(2500));
                if let Some(w) = window {
                    let _ = w.show();
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::locate_tshark,
            commands::set_tshark_path,
            commands::open_capture,
            commands::open_capture_data,
            commands::fetch_hex,
            commands::tshark_version,
            commands::save_text,
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
