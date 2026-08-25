import { describe, expect, it } from 'vitest'
import { tcpStatHint, tcpStatRows } from './tcpStatHints'

describe('tcpStatHint', () => {
  it('lost-segment:文案随缺失数变化', () => {
    expect(tcpStatHint('lost-segment', 1, 100)).toContain('1 个 segment')
    expect(tcpStatHint('lost-segment', 104, 1000)).toContain('104 个 segment')
  })

  it('占比 ≥10% 时升级为「大量」并带百分比', () => {
    const h = tcpStatHint('retransmission', 1305, 10000)
    expect(h).toContain('大量重传')
    expect(h).toContain('13.1%')
  })

  it('占比 <10% 且数量 >1:中性文案,不含「大量」', () => {
    const h = tcpStatHint('retransmission', 3, 1000)
    expect(h).toContain('3 次重传')
    expect(h).not.toContain('大量')
  })

  it('数量为 1:弱化措辞「仅」', () => {
    expect(tcpStatHint('retransmission', 1, 1000)).toContain('仅 1 次')
    expect(tcpStatHint('duplicate-ack', 1, 1000)).toContain('仅 1 个')
    expect(tcpStatHint('out-of-order', 1, 1000)).toContain('仅 1 个')
    expect(tcpStatHint('fast-retransmission', 1, 1000)).toContain('仅 1 次')
  })

  it('各类类型文案均提及自身关键词', () => {
    expect(tcpStatHint('fast-retransmission', 5, 1000)).toContain('快速重传')
    expect(tcpStatHint('duplicate-ack', 5, 1000)).toContain('重复 ACK')
    expect(tcpStatHint('out-of-order', 5, 1000)).toContain('乱序')
  })
})

describe('tcpStatRows', () => {
  it('条目映射为带标签名与解读的行', () => {
    const rows = tcpStatRows(
      [
        { key: 'retransmission', count: 1305 },
        { key: 'duplicate-ack', count: 2073 },
      ],
      10000,
    )
    expect(rows[0].label).toContain('重传')
    expect(rows[0].hint).toContain('大量')
    expect(rows[1].label).toContain('重复 ACK')
    expect(rows[1].hint).toContain('大量')
  })
})
