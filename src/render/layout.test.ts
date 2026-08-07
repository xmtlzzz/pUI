import { describe, expect, it } from 'vitest'
import { layoutSequence, CLIENT_X, SERVER_X } from './layout'
import type { Packet } from '../model/types'

function pkt(n: number, time: number, dir: 'request' | 'response' | 'other', info: string, len = 60): Packet {
  return { number: n, time, len, transport: 'tcp', proto: 'http', direction: dir, info }
}

const packets: Packet[] = [
  pkt(1, 0.0, 'request', 'TCP SYN'),
  pkt(2, 0.03, 'response', 'TCP SYN-ACK'),
  pkt(3, 0.05, 'request', 'HTTP GET /'),
]

describe('layoutSequence', () => {
  it('style A slants requests down-right and responses down-left', () => {
    const l = layoutSequence(packets, 'A', 'client', 'server')
    expect(l.messages).toHaveLength(3)
    const [a, b] = l.messages
    expect(a.x1).toBeLessThan(a.x2) // 请求:左→右
    expect(a.y1).toBeLessThan(a.y2) // 斜向下
    expect(b.x1).toBeGreaterThan(b.x2) // 响应:右→左
    expect(l.messages[2].info).toBe('HTTP GET /')
    expect(l.height).toBeGreaterThan(0)
  })

  it('style B lays rows with same y per message', () => {
    const l = layoutSequence(packets, 'B', 'client', 'server')
    expect(l.messages).toHaveLength(3)
    for (const m of l.messages) {
      expect(m.y1).toBe(m.y2)
      expect(m.x1).not.toBe(m.x2)
    }
  })

  it('carries number/time/len/direction into messages', () => {
    const l = layoutSequence(packets, 'B', 'client', 'server')
    const m = l.messages[0]
    expect(m.id).toBe(1)
    expect(m.time).toBe(0)
    expect(m.len).toBe(60)
    expect(m.direction).toBe('request')
  })

  it('uses client/server endpoint x positions', () => {
    const l = layoutSequence(packets, 'B', 'client', 'server')
    expect(CLIENT_X).toBeLessThan(SERVER_X)
    expect(l.width).toBeGreaterThan(0)
  })
})
