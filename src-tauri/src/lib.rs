pub mod commands;
pub mod tshark;

use std::sync::Arc;

use tauri::Manager;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        // 单实例锁(必须最先注册):再次点击 exe 时唤起已有窗口而非开新进程。
        // 用户实测多次点击产生多个实例;回调里 show+focus 保证「点了就有窗口」
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        // 页面加载完成即显示窗口:此时 index.html(含表情球启动层)已就绪,
        // 用户看到的是启动屏而非白屏;不依赖 React/JS(隐藏窗口会冻结 WebView2 rAF,
        // 若由前端 show 存在死锁路径)。2.5s 线程兜底继续保留。
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                let _ = webview.show();
            }
        })
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
            commands::save_bytes,
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
