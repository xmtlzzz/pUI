import { describe, expect, it } from 'vitest'
import { BOOT_MIN_DISPLAY_MS, bootRemovalDelay } from './bootTiming'

describe('启动层最短展示时长(过渡动画固定 2 秒,用户要求)', () => {
  it('React 早于 2 秒就绪:补足剩余时长后再撤下', () => {
    expect(bootRemovalDelay(0)).toBe(BOOT_MIN_DISPLAY_MS)
    expect(bootRemovalDelay(300)).toBe(1700)
    expect(bootRemovalDelay(1999)).toBe(1)
  })

  it('就绪已晚于 2 秒(bundle 慢):立即撤下,不再叠加等待', () => {
    expect(bootRemovalDelay(BOOT_MIN_DISPLAY_MS)).toBe(0)
    expect(bootRemovalDelay(4500)).toBe(0)
  })

  it('异常入参(负已展示时长)不产生异常输出:仍给足最短展示窗', () => {
    expect(bootRemovalDelay(-5)).toBe(BOOT_MIN_DISPLAY_MS + 5)
  })
})
