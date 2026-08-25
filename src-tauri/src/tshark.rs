use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tauri::Manager;

use crate::commands::AppState;

/// tshark `-T json` 输出上限:超过即终止子进程,防止超大抓包把内存打爆。
/// 128MB 与前端 parsePackets 守卫同档;配合 `-e` 精选字段(输出比全协议树小 4-5 倍)。
/// M0 新增 9 个分析字段后实测 TCP 密集抓包约 1082 → 1298 B/包(+19%),
/// 等效可开约 75-85MB 抓包(约 6.5-8 万包);DNS 等非 TCP 流量增幅仅 5% 左右
const MAX_CAPTURE_JSON: u64 = 128 * 1024 * 1024;
/// 单帧 hex 文本上限(正常 <1MB;恶意巨型帧由该上限兜底,防全量缓冲 OOM)
const MAX_HEX_TEXT: u64 = 32 * 1024 * 1024;
/// 子进程墙钟超时:超时 kill 并返回可读错误,防止挂死的 tshark 永久占线
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// stdout 已 EOF 但子进程未退出时的收尾宽限,超宽限 kill
const EXIT_GRACE: Duration = Duration::from_secs(5);
/// stderr 缓冲上限:恶意抓包可诱导逐包 dissector 错误风暴,无上限会在超时 kill 前积累数百 MB;
/// 超限后丢弃式继续排空(防子进程阻塞在写 stderr 上死锁),只停止追加
const MAX_STDERR: usize = 1024 * 1024;
/// 回传前端的错误信息截断长度:完整 stderr 可能达 MB 级,IPC 整体传输同样打内存
const MAX_ERR_MSG: usize = 4 * 1024;

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
    // 锁只覆盖「读缓存/写缓存」的短暂区间,resolve(可能 spawn where/which,耗时)在锁外执行,
    // 避免并发命令排队等待外部进程
    let cached = state.resolved_path.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(p) = cached {
        if p.exists() {
            return Some(p);
        }
    }
    let resolved = resolve(app, state);
    if let Some(p) = resolved.as_ref() {
        *state.resolved_path.lock().unwrap_or_else(|e| e.into_inner()) = Some(p.clone());
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

/// `-e` 精选字段清单:只取 pUI 解析层用到的字段,输出比全协议树(-J)小 4-5 倍。
/// 注意字段名为 tshark -G fields 的规范名(下划线,如 tcp.analysis.lost_segment);
/// 前端解析器同时兼容树形态的连字符键。新增前端字段时须同步此清单与 gen-parsed.mjs。
pub const CAPTURE_FIELDS: &[&str] = &[
    "frame.number",
    "frame.time_relative",
    "frame.time_epoch",
    "frame.interface_id",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.stream",
    "tcp.len",
    "tcp.completeness",
    "tcp.options.sack_le",
    "tcp.options.sack_re",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.duplicate_ack_num",
    "tcp.analysis.lost_segment",
    "tcp.analysis.spurious_retransmission",
    "udp.srcport",
    "udp.dstport",
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "http.time",
    "http.request.line",
    "http.response.line",
    "dns.qry.name",
    "dns.flags.response",
    "tls.handshake.type",
];

pub fn run_capture(bin: &Path, file: &str) -> Result<String, String> {
    if file.starts_with('-') {
        return Err("invalid capture path".into()); // 防 `-` 前缀选项混淆/`-r -` 卡读 stdin
    }
    // -e 平铺字段模式:每帧只输出 CAPTURE_FIELDS,替代全协议树(-J)的 4-5 倍体积。
    //
    // tcp.relative_sequence_numbers:FALSE 是分析引擎的硬前提:tshark 默认把 tcp.seq / tcp.ack /
    // tcp.options.sack_le/re 显示为相对 ISN 的序号,而 tcp.seq_raw 是原始序号——两种空间混在同一帧里。
    // 实测中途抓包(base seq 500001):线上 SACK 是 500201-500301,tshark 却解析成 201-301,
    // 若与 seq_raw 比较会凭空造出约 50 万字节的 Gap。关掉相对序号后 seq/ack/SACK 全部落在 raw 空间,
    // 从源头消掉这一类假阳性(实测该选项不改变 tcp.analysis.* 标签)。
    let mut args: Vec<&str> = vec!["-o", "tcp.relative_sequence_numbers:FALSE", "-r", file, "-T", "json"];
    for f in CAPTURE_FIELDS {
        args.push("-e");
        args.push(f);
    }
    run_stream(bin, &args, MAX_CAPTURE_JSON)
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

    // stderr 由专用线程并发排空,带字节上限(超限丢弃式排空防死锁),内容仅用于错误诊断
    let stderr_thread = child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let mut chunk = [0u8; 8192];
            let mut total = 0usize;
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if total < MAX_STDERR {
                            let take = n.min(MAX_STDERR - total);
                            let _ = s.push_str(&String::from_utf8_lossy(&chunk[..take]));
                            total += take;
                        }
                        // 超限:继续读但不追加,维持管道排空
                    }
                    Err(_) => break,
                }
            }
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
                let _ = tx.send(Err(format!(
                    "抓包解析输出超过 {}MB 上限:请先用显示过滤器缩小范围,或用 editcap/traceshark 分割后打开",
                    max_stdout / 1024 / 1024
                )));
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
    let err = truncate_err(&stderr_thread.and_then(|h| h.join().ok()).unwrap_or_default());
    if let Some(st) = status {
        if !st.success() {
            return Err(err.trim().to_string());
        }
    }
    Ok(String::from_utf8_lossy(&result.unwrap()).to_string())
}

/// 错误信息截断:完整 stderr 可达 MB 级,IPC 回传前裁到 MAX_ERR_MSG
fn truncate_err(s: &str) -> String {
    if s.len() <= MAX_ERR_MSG {
        return s.to_string();
    }
    let mut cut = MAX_ERR_MSG;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n…[truncated]", &s[..cut])
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
    if !out.status.success() {
        return None;
    }
    let hits: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    // 多个命中时按路径特征择优(优先 Wireshark 官方安装目录),其余按 PATH 顺序兜底
    hits.iter()
        .find(|p| prefers_wireshark_path(p))
        .cloned()
        .or_else(|| hits.first().cloned())
}

/// WSL 下的 /usr/bin/tshark 常是不完整移植,优先真实 Wireshark 安装
fn prefers_wireshark_path(p: &str) -> bool {
    let l = p.to_lowercase();
    (l.contains("wireshark") || l.contains("program files")) && !l.contains("wsl")
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
    fn truncate_err_caps_length_on_char_boundary() {
        let long = "x".repeat(10 * 1024);
        let cut = truncate_err(&long);
        assert!(cut.len() < 8 * 1024, "should be capped near 4KB: {}", cut.len());
        assert!(cut.ends_with("…[truncated]"));
        // 短文本原样返回
        assert_eq!(truncate_err("short"), "short");
        // 多字节字符不在中间截断(UTF-8 边界安全)
        let cjk = "汉".repeat(4000); // 12KB
        let cut_cjk = truncate_err(&cjk);
        assert!(cut_cjk.ends_with("…[truncated]"));
        assert!(cut_cjk.starts_with("汉"));
    }

    #[test]
    fn prefers_wireshark_path_favors_real_install() {
        assert!(prefers_wireshark_path("C:\\Program Files\\Wireshark\\tshark.exe"));
        assert!(prefers_wireshark_path("/usr/local/wireshark/bin/tshark"));
        assert!(!prefers_wireshark_path("/usr/bin/tshark"));
        assert!(!prefers_wireshark_path("/mnt/c/wsl/usr/bin/tshark"));
        assert!(!prefers_wireshark_path(""));
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
