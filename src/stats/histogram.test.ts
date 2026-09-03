import { describe, expect, it } from 'vitest'
import { buildHistogram, overlapRange, throughputBuckets } from './histogram'
import type { Conversation, Packet } from '../model/types'

function pkt(n: number, time: number): Packet {
  return { number: n, time, len: 60, transport: 'tcp', proto: 'tcp', direction: 'other' }
}

describe('buildHistogram', () => {
  it('按时间均分桶并计数', () => {
    const buckets = buildHistogram([pkt(1, 0), pkt(2, 10), pkt(3, 10), pkt(4, 20)], 2)
    expect(buckets).toHaveLength(2)
    expect(buckets[0].count).toBe(1) // time ∈ [0,10)
    expect(buckets[1].count).toBe(3) // time ∈ [10,20](含边界)
    expect(buckets[0].start).toBe(0)
    expect(buckets[1].end).toBe(20)
  })

  it('空输入与单时间点', () => {
    expect(buildHistogram([])).toEqual([])
    const b = buildHistogram([pkt(1, 5), pkt(2, 5)], 4)
    expect(b[0].count + b[1].count + b[2].count + b[3].count).toBe(2) // 跨度 0 时全部归一
    expect(b[0].count).toBe(2)
  })
})

describe('overlapRange', () => {
  function conv(id: string, start: number, end: number): Conversation {
    return { id, client: 'a', server: 'b', protocol: 'tcp', packetCount: 1, bytes: 60, start, end, duration: end - start, packets: [], issues: [] }
  }
  it('只保留与窗口重叠的会话', () => {
    const list = [conv('early', 0, 1), conv('mid', 5, 8), conv('later', 12, 15)]
    expect(overlapRange(list, { start: 6, end: 10 }).map((c) => c.id)).toEqual(['mid'])
    expect(overlapRange(list, { start: 0, end: 100 })).toHaveLength(3)
    expect(overlapRange(list, { start: 15, end: 16 }).map((c) => c.id)).toEqual(['later']) // 端点相接也算重叠
  })
})

describe('throughputBuckets — 按时间聚合的吞吐', () => {
  function p(n: number, time: number, len = 60, tcpLen?: number): Packet {
    return { number: n, time, len, transport: 'tcp', proto: 'tcp', direction: 'other', tcpLen }
  }

  it('空输入返回空数组;无 tcpLen 时按 frame.len 累计字节', () => {
    expect(throughputBuckets([])).toEqual([])
    const b = throughputBuckets([p(1, 0, 100), p(2, 5, 200)], 2)
    expect(b[0].bytes).toBe(100)
    expect(b[1].bytes).toBe(200)
  })

  it('字节按 tcpLen 累计(有 tcpLen 时不用 frame.len)', () => {
    const b = throughputBuckets([p(1, 0, 60, 100), p(2, 5, 60, 200)], 2)
    expect(b[0].bytes).toBe(100)
    expect(b[1].bytes).toBe(200)
    expect(b[0].packets).toBe(1)
  })

  it('单桶时全部报文归入唯一桶,字节/报文数分别为总数', () => {
    const b = throughputBuckets([p(1, 0, 60, 10), p(2, 3, 60, 20), p(3, 7, 60, 30)], 1)
    expect(b).toHaveLength(1)
    expect(b[0].bytes).toBe(60)
    expect(b[0].packets).toBe(3)
  })

  it('跨桶边界按时间归属:桶内累计各自区间', () => {
    // 时间轴 [0,20] 均分 2 桶,边界在 10:#1(0)、#2(9) 在左桶,#3(20,末端钳制)在右桶
    const b = throughputBuckets([p(1, 0, 60, 10), p(2, 9, 60, 20), p(3, 20, 60, 30)], 2)
    expect(b).toHaveLength(2)
    expect(b[0].bytes).toBe(30) // time ∈ [0,10):#1+#2
    expect(b[1].bytes).toBe(30) // time ∈ [10,20]:#3
    expect(b[0].packets).toBe(2)
    expect(b[1].packets).toBe(1)
  })

  it('桶计数之和恒等于总字节/总报文数(任意输入确定性)', () => {
    const pkts = Array.from({ length: 20 }, (_, i) => p(i + 1, i * 0.7, 60, (i * 137) % 1000))
    const b = throughputBuckets(pkts, 7)
    expect(b.reduce((s, x) => s + x.bytes, 0)).toBe(pkts.reduce((s, x) => s + (x.tcpLen ?? x.len), 0))
    expect(b.reduce((s, x) => s + x.packets, 0)).toBe(pkts.length)
  })

  it('随机输入不变量:空输入 available=空数组;桶计数之和=总数;字节≥0;时间轴首尾与输入一致', () => {
    for (let trial = 0; trial < 30; trial++) {
      const n = trial % 7 // 含 0 个的抖动
      const pkts = Array.from({ length: n }, (_, i) => p(i + 1, (i * 97) % 17, 60, (i * 31) % 500))
      if (n === 0) {
        expect(throughputBuckets(pkts)).toEqual([])
        continue
      }
      const b = throughputBuckets(pkts, 1 + (trial % 5))
      expect(b.reduce((s, x) => s + x.packets, 0)).toBe(n)
      expect(b.reduce((s, x) => s + x.bytes, 0)).toBe(pkts.reduce((s, x) => s + (x.tcpLen ?? x.len), 0))
      expect(b.every((x) => x.bytes >= 0 && x.packets >= 0)).toBe(true)
      expect(b[0]!.start).toBe(Math.min(...pkts.map((q) => q.time)))
      expect(b[b.length - 1]!.end).toBe(Math.max(...pkts.map((q) => q.time)))
    }
  })
})
