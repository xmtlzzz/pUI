use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tauri::Manager;

use crate::commands::AppState;

/// tshark `-T json` 输出上限:超过即终止子进程,防止超大抓包把内存打爆。
/// 64MB 与前端 parsePackets 守卫同档:JSON.parse 的对象图放大 4-8 倍仍可控
const MAX_CAPTURE_JSON: u64 = 64 * 1024 * 1024;
/// 单帧 hex 文本上限(正常 <1MB;恶意巨型帧由该上限兜底,防全量缓冲 OOM)
const MAX_HEX_TEXT: u64 = 32 * 1024 * 1024;
/// 子进程墙钟超时:超时 kill 并返回可读错误,防止挂死的 tshark 永久占线
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// stdout 已 EOF 但子进程未退出时的收尾宽限,超宽限 kill
const EXIT_GRACE: Duration = Duration::from_secs(5);

pub fn resolve(app: &tauri::AppHandle, state: &AppState) -> Option<PathBuf> {
    // ① 用户设置路径
    if let Some(p) = state.tshark_path.lock().unwrap_or_else(|e| e.into_inner()).clone() {
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
    let mut cache = state.resolved_path.lock().unwrap_or_else(|e| e.into_inner());
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
    run_stream(
        bin,
        &["-r", file, "-T", "json", "-J", "frame eth ip ipv6 tcp udp http dns tls"],
        MAX_CAPTURE_JSON,
    )
}

/// 流式读取子进程 stdout,带字节上限 + 墙钟超时 + stderr 并发排空:
/// - 上限:防止 `Command::output()` 把多 GB JSON 全量缓冲进内存;
/// - 超时:挂死的子进程在时限内被 kill+wait 回收,避免线程/进程永久泄漏;
/// - stderr 并发排空:错误风暴(>64KB stderr)不会把子进程阻塞在写 stderr 上造成死锁。
fn run_stream(bin: &Path, args: &[&str], max_stdout: u64) -> Result<String, String> {
    run_stream_with_timeout(bin, args, max_stdout, COMMAND_TIMEOUT)
}

fn run_stream_with_timeout(
    bin: &Path,
    args: &[&str],
    max_stdout: u64,
    timeout: Duration,
) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    hide_console(&mut cmd);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to run tshark: {e}"))?;

    let mut stdout = child.stdout.take().ok_or("tshark: no stdout")?;

    // stderr 由专用线程并发排空,内容仅用于错误诊断
    let stderr_thread = child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        })
    });

    // stdout 由专用线程分块读取并设字节上限
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, String>>();
    let reader = std::thread::spawn(move || {
        let mut buf: Vec<u8> = Vec::new();
        let mut total: u64 = 0;
        let mut chunk = [0u8; 65536];
        loop {
            let n = match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Err(format!("tshark stdout: {e}")));
                    return;
                }
            };
            total += n as u64;
            if total > max_stdout {
                let _ = tx.send(Err("capture too large: tshark output exceeds limit".into()));
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = tx.send(Ok(buf));
    });

    let deadline = Instant::now() + timeout;
    let mut out: Option<Result<Vec<u8>, String>> = None;
    let mut status: Option<std::process::ExitStatus> = None;
    loop {
        if out.is_none() {
            if let Ok(r) = rx.try_recv() {
                out = Some(r);
            }
        }
        if status.is_none() {
            if let Ok(Some(st)) = child.try_wait() {
                status = Some(st);
            }
        }
        // 输出出错立即收尾;输出正常则等子进程退出(拿到退出码)
        let done = match &out {
            Some(Err(_)) => true,
            Some(Ok(_)) => status.is_some(),
            None => false,
        };
        if done {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            let _ = stderr_thread.map(|h| h.join());
            return Err("tshark timed out".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let result = out.unwrap();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        let _ = stderr_thread.map(|h| h.join());
        return result.map(|b| String::from_utf8_lossy(&b).to_string());
    }
    // stdout 已 EOF 但子进程未退出:宽限等待,超宽限 kill
    if status.is_none() {
        let grace = Instant::now() + EXIT_GRACE;
        while status.is_none() && Instant::now() < grace {
            if let Ok(Some(st)) = child.try_wait() {
                status = Some(st);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    let _ = reader.join();
    let err = stderr_thread.and_then(|h| h.join().ok()).unwrap_or_default();
    if let Some(st) = status {
        if !st.success() {
            return Err(err.trim().to_string());
        }
    }
    Ok(String::from_utf8_lossy(&result.unwrap()).to_string())
}

/// 从 `tshark -v` 输出首行提取版本号:"TShark (Wireshark) 4.2.5 …" → "4.2.5"
pub fn parse_version_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix("TShark (Wireshark)")?;
    let token = rest.trim_start().split_whitespace().next()?;
    Some(token.to_string())
}

pub fn tshark_version(bin: &Path) -> Option<String> {
    // -v 输出(版本+版权信息)远小于 64KB,复用流式读取的防挂死/超时保护
    let out = run_stream(bin, &["-v"], 64 * 1024).ok()?;
    out.lines().find_map(parse_version_line)
}

pub fn run_hex(bin: &Path, file: &str, number: u32) -> Result<String, String> {
    if file.starts_with('-') {
        return Err("invalid capture path".into());
    }
    let filter = format!("frame.number=={number}");
    // 复用流式读取 + 上限:单帧 hex 通常 <1MB,恶意巨型帧由 MAX_HEX_TEXT 兜底
    run_stream(bin, &["-r", file, "-Y", &filter, "-x"], MAX_HEX_TEXT)
}

#[cfg(windows)]
fn hide_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000; // 不创建新控制台窗口
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_cmd: &mut Command) {}

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
    fn run_stream_caps_oversized_output() {
        // 子进程输出超过上限时应立即终止并报错,而非全量缓冲进内存
        let (bin, args): (&str, Vec<&str>) = if cfg!(windows) {
            ("cmd", vec!["/C", "echo aaaaaaaaaaaaaaaaaaaa"])
        } else {
            ("/bin/sh", vec!["-c", "echo aaaaaaaaaaaaaaaaaaaa"])
        };
        assert!(run_stream(Path::new(bin), &args, 4).is_err());
        // 小输出正常返回
        assert!(run_stream(Path::new(bin), &args, 1024).is_ok());
    }

    #[test]
    fn parse_version_line_extracts_version() {
        assert_eq!(parse_version_line("TShark (Wireshark) 4.2.5 (v4.2.5-0-g0a45a5e2)").as_deref(), Some("4.2.5"));
        assert_eq!(parse_version_line("TShark (Wireshark) 3.6.1").as_deref(), Some("3.6.1"));
        assert_eq!(parse_version_line("  TShark (Wireshark) 99.0  ").as_deref(), Some("99.0"));
        assert_eq!(parse_version_line("just some noise"), None);
        assert_eq!(parse_version_line(""), None);
    }

    #[test]
    fn tshark_version_handles_missing_binary() {
        assert_eq!(tshark_version(Path::new("/nonexistent/tshark")), None);
    }

    #[test]
    fn run_stream_kills_hanging_child_on_timeout() {
        // 子进程只睡不输出不退出:超时应 kill 并返回 Err,而非永久阻塞
        let (bin, args): (&str, Vec<&str>) = if cfg!(windows) {
            ("powershell.exe", vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
        } else {
            ("/bin/sh", vec!["-c", "sleep 60"])
        };
        let start = std::time::Instant::now();
        let out = run_stream_with_timeout(
            Path::new(bin),
            &args,
            1024 * 1024,
            std::time::Duration::from_millis(800),
        );
        assert!(out.is_err(), "expected timeout error, got {:?}", out);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "timeout kill too slow: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn run_stream_drains_stderr_without_deadlock() {
        // stderr 灌满管道(>64KB)不应阻塞子进程:并发排空后应正常读到 stdout
        let (bin, args): (&str, Vec<&str>) = if cfg!(windows) {
            (
                "powershell.exe",
                vec![
                    "-NoProfile",
                    "-Command",
                    "for($i=0;$i -lt 4000;$i++){ [Console]::Error.WriteLine(('x'*400)) }; Write-Output 'done'",
                ],
            )
        } else {
            (
                "/bin/sh",
                vec![
                    "-c",
                    "i=0; while [ $i -lt 4000 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >&2; i=$((i+1)); done; echo done",
                ],
            )
        };
        let out = run_stream_with_timeout(
            Path::new(bin),
            &args,
            4 * 1024 * 1024,
            std::time::Duration::from_secs(30),
        );
        assert!(out.is_ok(), "stderr flood deadlocked or failed: {out:?}");
        assert!(out.unwrap_or_default().contains("done"));
    }

    #[test]
    fn run_hex_caps_oversized_output() {
        // 单帧 hex 文本超上限应报错而非全量缓冲(防恶意巨型帧 OOM)
        let (bin, args): (&str, Vec<&str>) = if cfg!(windows) {
            (
                "powershell.exe",
                vec![
                    "-NoProfile",
                    "-Command",
                    "1..64 | ForEach-Object { [Console]::Out.Write(('x'*1048576)) }",
                ],
            )
        } else {
            ("/bin/sh", vec!["-c", "yes x | head -c 67108864"])
        };
        let out = run_stream_with_timeout(
            Path::new(bin),
            &args,
            32 * 1024 * 1024,
            std::time::Duration::from_secs(60),
        );
        assert!(out.is_err(), "oversized output should be capped: {out:?}");
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
