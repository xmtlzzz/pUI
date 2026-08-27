import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { computeCaptureQuality } from './captureQuality'

/**
 * M5 Capture Quality:采集完整性统计(plan M5)。
 * 红线:截断(frame.cap_len < frame.len)是**采集侧信号**(snaplen/镜像口/ring buffer),
 * 绝不是网络丢包证据 —— 措辞必须区分"抓包工具没抓全"与"网络没送到"。
 */

const P = (o: Partial<Packet> & { number: number }): Packet =>
  ({ time: o.number * 0.01, len: 100, transport: 'tcp', proto: 'tcp', direction: 'other', ...o }) as Packet

describe('computeCaptureQuality — 采集完整性', () => {
  it('全部完整:truncated=0,available=true,无截断比例', () => {
    const q = computeCaptureQuality([P({ number: 1 }), P({ number: 2, capLen: 100 }), P({ number: 3, capLen: 100 })])
    expect(q.truncatedCount).toBe(0)
    expect(q.available).toBe(true)
    expect(q.truncatedRatio).toBe(0)
  })

  it('有截断:计数与比例正确,截断报文号列出', () => {
    const packets = [
      P({ number: 1 }),
      P({ number: 2, capLen: 54 }), // 100B 只抓到 54B
      P({ number: 3, capLen: 100 }), // 完整捕获
      P({ number: 4, capLen: 60 }),
    ]
    const q = computeCaptureQuality(packets)
    expect(q.available).toBe(true)
    expect(q.truncatedCount).toBe(2) // #2/#4 截断
    // 分母 = 带 capLen 字段的报文数(#2/#3/#4):#1 无字段不参与统计
    expect(q.truncatedRatio).toBeCloseTo(2 / 3, 5)
    expect(q.truncatedPackets).toEqual([2, 4])
  })

  it('capLen 缺失的旧抓包:available=false(无数据不断言)', () => {
    const q = computeCaptureQuality([P({ number: 1 }), P({ number: 2 })])
    expect(q.available).toBe(false)
    expect(q.truncatedCount).toBe(0)
    expect(q.truncatedPackets).toEqual([])
  })

  it('部分缺失 capLen:按有字段的报文统计,available 仍为 true', () => {
    // #1 无 capLen 字段不计入分母;#2 截断、#3 完整 → ratio = 1/2
    const q = computeCaptureQuality([P({ number: 1 }), P({ number: 2, capLen: 30 }), P({ number: 3, capLen: 100 })])
    expect(q.available).toBe(true)
    expect(q.truncatedCount).toBe(1)
    expect(q.truncatedRatio).toBeCloseTo(0.5, 5)
  })

  it('空输入 unavailable;同输入两次结果一致', () => {
    expect(computeCaptureQuality([]).available).toBe(false)
    const packets = [P({ number: 1, capLen: 50 }), P({ number: 2 })]
    expect(JSON.stringify(computeCaptureQuality(packets))).toBe(JSON.stringify(computeCaptureQuality(packets)))
  })
})
