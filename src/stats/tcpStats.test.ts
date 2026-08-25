import { describe, expect, it } from 'vitest'
import { deriveTcpStats } from './tcpStats'
import type { Packet } from '../model/types'

function pkt(n: number, analysis?: string[]): Packet {
  return { number: n, time: n, len: 60, transport: 'tcp', proto: 'tcp', direction: 'other', tcpAnalysis: analysis }
}

describe('deriveTcpStats', () => {
  it('按报文级计数五类标签,按固定顺序输出', () => {
    const s = deriveTcpStats([
      pkt(1, ['retransmission']),
      pkt(2, ['retransmission']),
      pkt(3, ['fast-retransmission']),
      pkt(4, ['duplicate-ack']),
      pkt(5, ['duplicate-ack']),
      pkt(6, ['duplicate-ack']),
      pkt(7, ['lost-segment']),
      pkt(8, ['out-of-order']),
      pkt(9),
    ])
    expect(s).toEqual([
      { key: 'retransmission', count: 2 },
      { key: 'fast-retransmission', count: 1 },
      { key: 'duplicate-ack', count: 3 },
      { key: 'lost-segment', count: 1 },
      { key: 'out-of-order', count: 1 },
    ])
  })

  it('数量为 0 的类型不输出', () => {
    expect(deriveTcpStats([pkt(1), pkt(2)])).toEqual([])
  })

  it('同一报文带多个标签时各标签分别计数', () => {
    const s = deriveTcpStats([pkt(1, ['retransmission', 'out-of-order'])])
    expect(s).toEqual([
      { key: 'retransmission', count: 1 },
      { key: 'out-of-order', count: 1 },
    ])
  })

  it('未知标签忽略', () => {
    expect(deriveTcpStats([pkt(1, ['bogus-tag'])])).toEqual([])
  })
})
