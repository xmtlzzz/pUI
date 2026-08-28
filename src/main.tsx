import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { isTauri } from "./bridge/tauri";

/** 窗口可见性(tauri.conf visible:false):React 首帧后再显示 —— WebView2 初始化
 *  与 bundle 加载期间用户看到的是「无窗口」而非白屏;index.html 的表情球加载层
 *  覆盖首帧到 React 挂载之间的间隙。JS 万一失败由 Rust 侧 2.5s 兜底强制显示。 */
async function showWindowWhenReady(): Promise<void> {
  if (!isTauri()) return
  try {
    const { getCurrentWindow } = await import('@tauri-apps/api/window')
    await getCurrentWindow().show()
  } catch {
    /* 显示失败时由 Rust 兜底,不阻塞渲染 */
  }
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

// 首帧渲染后:显示窗口 + 淡出启动加载层(rAF 保证 React 已提交 DOM)。
// 隐藏窗口会冻结 WebView2 的 rAF,因此另设 3s 定时兜底 —— 双路竞争,先到先得,
// teardown 幂等(boot 节点已移除时为空操作)
let bootGone = false
function removeBoot(): void {
  if (bootGone) return
  bootGone = true
  const boot = document.getElementById("boot")
  if (!boot) return
  boot.classList.add("bye")
  window.setTimeout(() => {
    // 先停 emotion-ball 引擎(内置 RAF),再移除启动层节点
    const teardown = (window as { __puiBootTeardown?: () => void }).__puiBootTeardown
    try {
      teardown?.()
    } catch {
      /* 忽略 */
    }
    boot.remove()
  }, 300)
}
requestAnimationFrame(() => {
  void showWindowWhenReady()
  removeBoot()
});
// 兜底:rAF 被冻结(窗口隐藏期)/异常时,3s 后强制撤下启动层
window.setTimeout(removeBoot, 3000);
