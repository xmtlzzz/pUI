/** 启动层最短展示时长(ms):emotion-ball 过渡动画固定给足 2 秒 ——
 *  即使 React 已提前就绪也补足展示,避免「闪一下就没了」(用户要求)。
 *  Rust 侧 2.5s 强制显示兜底不受影响;3s 撤下兜底落在展示窗之后,不冲突。 */
export const BOOT_MIN_DISPLAY_MS = 2000

/** 启动层撤下延时:已展示时长 + 返回值 ≥ 最短展示时长;已超时则为 0(立即撤下) */
export function bootRemovalDelay(elapsedMs: number): number {
  return Math.max(0, BOOT_MIN_DISPLAY_MS - elapsedMs)
}
