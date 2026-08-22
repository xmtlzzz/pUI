import { describe, expect, it } from 'vitest'
import { formatEpoch } from './timeFormat'

describe('formatEpoch', () => {
  it('格式化本地时间 HH:MM:SS.mmm', () => {
    // 用已知 epoch 断言格式而非具体值(避免时区敏感)
    expect(formatEpoch(0)).toMatch(/^\d{2}:\d{2}:\d{2}\.\d{3}$/)
  })

  it('对 2020-06-01 00:00:00 UTC 输出一致格式', () => {
    expect(formatEpoch(Date.UTC(2020, 5, 1) / 1000)).toMatch(/^\d{2}:\d{2}:\d{2}\.000$/)
  })
})
