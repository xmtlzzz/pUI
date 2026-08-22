import { describe, expect, it } from 'vitest'
import { segmentConversation } from './segmentConversation'
import type { Packet } from '../model/types'

function pkt(n: number, t: number): Packet {
  return { number: n, time: t, len: 60, transport: 'tcp', proto: 'tcp', direction: 'other' }
}

describe('segmentConversation', () => {
  it('相邻间隔超过阈值切段', () => {
    const segs = segmentConversation([pkt(1, 0), pkt(2, 0.2), pkt(3, 2.0), pkt(4, 2.1)], 1.0)
    expect(segs).toHaveLength(2)
    expect(segs[0].packetCount).toBe(2)
    expect(segs[1].packetCount).toBe(2)
    expect(segs[1].start).toBe(2.0)
  })

  it('无空闲间隔时只有一段', () => {
    const segs = segmentConversation([pkt(1, 0), pkt(2, 0.1), pkt(3, 0.2)], 1.0)
    expect(segs).toHaveLength(1)
    expect(segs[0].packetCount).toBe(3)
    expect(segs[0].bytes).toBe(180)
  })

  it('空输入返回空', () => {
    expect(segmentConversation([])).toEqual([])
  })

  it('阈值可调', () => {
    const segs = segmentConversation([pkt(1, 0), pkt(2, 0.5)], 0.3)
    expect(segs).toHaveLength(2)
    expect(segmentConversation([pkt(1, 0), pkt(2, 0.5)], 1.0)).toHaveLength(1)
  })
})