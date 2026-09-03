import { describe, expect, it } from 'vitest'
import { computeFlowLayout, MAX_FLOW_ROWS } from './flowTimeline'
import type { Packet } from '../model/types'

function pkt(
  n: number,
  time: number,
  dir: 'request' | 'response' | 'other',
  info: string,
  opts: Partial<Packet> = {},
): Packet {
  return { number: n, time, len: 60, transport: 'tcp', proto: 'http', direction: dir, info, ...opts }
}

const packets: Packet[] = [
  pkt(1, 0.0, 'request', 'TCP SYN'),
  pkt(2, 0.03, 'response', 'TCP SYN-ACK'),
  pkt(3, 0.05, 'request', 'HTTP GET /'),
]

describe('computeFlowLayout 基本布局', () => {
  it('每个报文一行,行 y 从上到下单调递增(时间流形态)', () => {
    const l = computeFlowLayout(packets, { client: '192.168.1.10:54321' })
    expect(l.rows).toHaveLength(3)
    for (let i = 1; i < l.rows.length; i++) {
      expect(l.rows[i].y).toBeGreaterThan(l.rows[i - 1].y)
    }
  })

  it('携带帧号/时间/长度/协议/info,供行内标注「#帧号 协议概要 · 长度」', () => {
    const l = computeFlowLayout(packets, { client: '192.168.1.10:54321' })
    const r = l.rows[2]
    expect(r.number).toBe(3)
    expect(r.time).toBe(0.05)
    expect(r.len).toBe(60)
    expect(r.proto).toBe('http')
    expect(r.info).toBe('HTTP GET /')
    // 标注文本拼装完成,组件不再各自格式化
    expect(r.label).toContain('#3')
    expect(r.label).toContain('HTTP GET /')
    expect(r.label).toContain('60')
  })

  it('确定性:同输入两次调用输出深相等', () => {
    const a = computeFlowLayout(packets, { client: '192.168.1.10:54321' })
    const b = computeFlowLayout(packets, { client: '192.168.1.10:54321' })
    expect(a).toEqual(b)
  })

  it('空数组:0 行,高度为顶部预留(不抛错)', () => {
    const l = computeFlowLayout([], { client: 'a' })
    expect(l.rows).toHaveLength(0)
    expect(l.height).toBeGreaterThan(0)
  })
})

describe('computeFlowLayout 方向判定', () => {
  it('request 向右(a2b),response 向左(b2a)', () => {
    const l = computeFlowLayout(packets, { client: '192.168.1.10:54321' })
    expect(l.rows[0].dir).toBe('a2b')
    expect(l.rows[1].dir).toBe('b2a')
  })

  it("'other' 方向按 srcIp 是否等于 client 判定:相等画 a2b", () => {
    const p = pkt(9, 0.1, 'other', 'TCP', { srcIp: '192.168.1.10', dstIp: '93.184.216.34' })
    const l = computeFlowLayout([p], { client: '192.168.1.10:54321' })
    expect(l.rows[0].dir).toBe('a2b')
  })

  it("'other' 且 srcIp 等于 server 侧 → b2a", () => {
    const p = pkt(9, 0.1, 'other', 'TCP', { srcIp: '93.184.216.34', dstIp: '192.168.1.10' })
    const l = computeFlowLayout([p], { client: '192.168.1.10:54321', server: '93.184.216.34:80' })
    expect(l.rows[0].dir).toBe('b2a')
  })

  it("'other' 且两侧都判不了 → neutral(中性短横线)", () => {
    const p = pkt(9, 0.1, 'other', 'TCP', { srcIp: '10.0.0.1', dstIp: '10.0.0.2' })
    const l = computeFlowLayout([p], { client: '192.168.1.10:54321' })
    expect(l.rows[0].dir).toBe('neutral')
  })
})

describe('computeFlowLayout 异常行标记', () => {
  it('tcpAnalysis 非空的报文 anomaly=true,其余 false', () => {
    const ps = [
      pkt(1, 0.0, 'request', 'TCP SYN'),
      pkt(2, 0.03, 'response', 'TCP Retransmission', { tcpAnalysis: ['retransmission'] }),
      pkt(3, 0.05, 'request', 'TCP', { tcpAnalysis: [] }),
    ]
    const l = computeFlowLayout(ps, { client: 'c' })
    expect(l.rows[0].anomaly).toBe(false)
    expect(l.rows[1].anomaly).toBe(true)
    expect(l.rows[2].anomaly).toBe(false) // 空数组不算异常
  })
})

describe('computeFlowLayout 时间刻度列', () => {
  it('每行自带时刻文本,密度可控', () => {
    const l = computeFlowLayout(packets, { client: 'c' })
    expect(l.rows[0].timeLabel).toBe('0.000')
    expect(l.rows[1].timeLabel).toBe('0.030')
  })

  it('刻度抽稀:tickEvery=3 时仅每 3 行输出一个刻度(首行保底)', () => {
    const ps = Array.from({ length: 10 }, (_, i) => pkt(i + 1, i * 0.1, 'request', 'TCP'))
    const l = computeFlowLayout(ps, { client: 'c', tickEvery: 3 })
    const ticks = l.ticks
    expect(ticks.length).toBeGreaterThan(0)
    expect(ticks[0].rowIndex).toBe(0) // 首行保底
    for (const t of ticks) expect(t.rowIndex % 3).toBe(0)
    // 确定性
    expect(ticks).toEqual(computeFlowLayout(ps, { client: 'c', tickEvery: 3 }).ticks)
  })

  it('tickEvery 未指定时默认全部行都有刻度(短会话不抽稀)', () => {
    const l = computeFlowLayout(packets, { client: 'c' })
    expect(l.ticks).toHaveLength(3)
  })
})

describe('computeFlowLayout 2000 行截断', () => {
  it('超过 MAX_FLOW_ROWS 截断并给出提示与原始总数,首尾保底', () => {
    const ps = Array.from({ length: 5000 }, (_, i) => pkt(i + 1, i * 0.001, 'request', 'TCP'))
    const l = computeFlowLayout(ps, { client: 'c' })
    expect(l.rows.length).toBeLessThanOrEqual(MAX_FLOW_ROWS)
    expect(l.truncated).toBe(true)
    expect(l.total).toBe(5000)
    // 尾包保底:最后一个报文必须可见(TCP 结尾 FIN/RST 是排障关键)
    expect(l.rows[l.rows.length - 1].number).toBe(5000)
    // 首包保底
    expect(l.rows[0].number).toBe(1)
    // 截断后行 y 仍单调(视觉不回折)
    for (let i = 1; i < l.rows.length; i++) {
      expect(l.rows[i].y).toBeGreaterThan(l.rows[i - 1].y)
    }
  })

  it('total % stride === 1(采样恰好命中末尾包)时不产生重复 packetNumber 行', () => {
    // total=2501,stride=ceil(2501/2000)=2 → 采样 i=0,2,...,2500 恰好命中最后一包,
    // 旧实现 else-if(w<maxRows) 会把尾包再次 push → 重复行(同 packetNumber 两个 React key)
    const ps = Array.from({ length: 2501 }, (_, i) => pkt(i + 1, i * 0.001, 'request', 'TCP'))
    const l = computeFlowLayout(ps, { client: 'c' })
    const nums = l.rows.map((r) => r.number)
    expect(new Set(nums).size).toBe(nums.length)
    expect(l.truncated).toBe(true)
    // 尾包保底:最后一包可见(本次采样已命中,无需追加)
    expect(nums[nums.length - 1]).toBe(2501)
  })

  it('未超上限 truncated=false,total=行数', () => {
    const l = computeFlowLayout(packets, { client: 'c' })
    expect(l.truncated).toBe(false)
    expect(l.total).toBe(3)
  })

  it('高度随行数线性增长且不超上限 DOM 高度', () => {
    const ps = Array.from({ length: 5000 }, (_, i) => pkt(i + 1, i * 0.001, 'request', 'TCP'))
    const l = computeFlowLayout(ps, { client: 'c' })
    expect(l.height).toBe(l.rows[l.rows.length - 1].y + l.rowHeight)
  })
})
