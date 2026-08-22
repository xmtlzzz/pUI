import { describe, expect, it } from 'vitest'
import { buildHistogram, overlapRange } from './histogram'
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
