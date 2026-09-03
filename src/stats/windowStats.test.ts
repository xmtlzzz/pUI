import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { computeWindowStats, windowTimeline } from './windowStats'

/**
 * M5 窗口变化统计:接收窗口通告的演化(两方向合并呈现对端接收侧)。
 * 红线:窗口字节数是对端**通告值**,单观察点只见通告不见实际缓冲区;
 * 字段缺失时 available=false,不编造。
 */

const P = (o: Partial<Packet> & { number: number; time: number }): Packet =>
  ({ len: 60, transport: 'tcp', proto: 'tcp', direction: 'other', tcpFlags: '0x0010', ...o }) as Packet

/** c2s 数据段(源 10.0.0.1:5000 → 80) */
const C = (o: Partial<Packet> & { number: number; time: number }) =>
  P({ srcIp: '10.0.0.1', srcPort: 5000, dstIp: '10.0.0.2', dstPort: 80, tcpFlags: '0x0018', tcpLen: 100, ...o })
/** s2c 纯 ACK,通告窗口 w */
const Sw = (n: number, w: number) =>
  P({ number: n, time: n * 0.01, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 5000, tcpLen: 0, tcpWindow: w })

describe('computeWindowStats — 接收窗口变化', () => {
  /** 数据段被 #2..#6 的 ACK 确认;窗口通告沿:65535 → 8760 → 8760 → 17520 → 65535 */
  const chain = (): Packet[] => [
    C({ number: 1, time: 0, tcpFlags: '0x0018', tcpLen: 100 }),
    Sw(2, 65535),
    C({ number: 3, time: 0.1, tcpLen: 100 }),
    Sw(4, 8760), // 收缩
    Sw(5, 8760), // 重复通告(不计变化)
    Sw(6, 17520),
    Sw(7, 65535),
  ]

  it('样本数/最小/最大/变化次数(相邻不同值才计一次)', () => {
    const stats = computeWindowStats(chain())
    expect(stats.available).toBe(true)
    expect(stats.samples).toBe(5) // #2/#4/#5/#6/#7 共 5 个带窗口的 ACK
    expect(stats.minBytes).toBe(8760)
    expect(stats.maxBytes).toBe(65535) // 通告沿 65535→8760→8760→17520→65535,最大即首尾
    expect(stats.changes).toBe(3) // 65535→8760、8760→17520、17520→65535;重复通告(8760)不计
  })

  it('窗口归零事件次数单列(零窗口语义由 m5Events 权威判定,这里只计数)', () => {
    const packets = [
      C({ number: 1, time: 0, tcpFlags: '0x0018', tcpLen: 100 }),
      Sw(2, 65535),
      Sw(3, 0),
      Sw(4, 0),
      Sw(5, 8760),
    ]
    const stats = computeWindowStats(packets)
    expect(stats.zeroCount).toBe(1) // 连续 0 合并为一期
    expect(stats.minBytes).toBe(0)
  })

  it('窗口字段全缺失:available=false', () => {
    const packets = [
      C({ number: 1, time: 0, tcpLen: 100 }),
      P({ number: 2, time: 0.01, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 5000, tcpLen: 0 }),
    ]
    const stats = computeWindowStats(packets)
    expect(stats.available).toBe(false)
    expect(stats.samples).toBe(0)
    expect(stats.minBytes).toBeUndefined()
  })

  it('混合缺失:按有字段的报文统计', () => {
    const packets = [
      C({ number: 1, time: 0, tcpFlags: '0x0018', tcpLen: 100 }),
      Sw(2, 65535),
      P({ number: 3, time: 0.1, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 5000 }), // 无窗口字段
      Sw(4, 8760),
      Sw(5, 8760),
      Sw(6, 17520),
      Sw(7, 8760),
      Sw(8, 8760),
    ]
    const stats = computeWindowStats(packets)
    expect(stats.available).toBe(true)
    expect(stats.samples).toBe(6) // 6 个带窗口字段(#3 缺失不计)
    expect(stats.minBytes).toBe(8760)
    expect(stats.changes).toBe(3) // 65535→8760→17520→8760
  })

  it('非 TCP/空输入;确定性', () => {
    expect(computeWindowStats([]).available).toBe(false)
    const packets = [
      C({ number: 1, time: 0, tcpFlags: '0x0018', tcpLen: 100 }),
      Sw(2, 8760),
      Sw(3, 8760),
    ]
    expect(JSON.stringify(computeWindowStats(packets))).toBe(JSON.stringify(computeWindowStats(packets)))
  })
})

describe('windowTimeline — 窗口通告随时间的变化曲线', () => {
  /** 数据段被 #2..#6 的 ACK 确认;窗口通告沿:65535 → 8760 → 8760 → 17520 → 65535 */
  const chain = (): Packet[] => [
    C({ number: 1, time: 0, tcpFlags: '0x0018', tcpLen: 100 }),
    Sw(2, 65535),
    C({ number: 3, time: 0.1, tcpLen: 100 }),
    Sw(4, 8760), // 收缩
    Sw(5, 8760), // 重复通告(不产生新样本)
    Sw(6, 17520),
    Sw(7, 65535),
  ]

  it('无窗口字段/空输入 → 空曲线', () => {
    expect(windowTimeline([])).toEqual([])
    expect(windowTimeline([C({ number: 1, time: 0, tcpLen: 100 })])).toEqual([])
  })

  it('每个「不同值通告」一个样本:首样本 + 变化点,重复通告跳过', () => {
    const tl = windowTimeline(chain())
    expect(tl).toEqual([
      { time: 0.02, windowBytes: 65535 },
      { time: 0.04, windowBytes: 8760 },
      { time: 0.06, windowBytes: 17520 },
      { time: 0.07, windowBytes: 65535 },
    ])
  })

  it('单个窗口通告 → 单样本', () => {
    expect(windowTimeline([Sw(2, 65535)])).toEqual([{ time: 0.02, windowBytes: 65535 }])
  })

  it('输入乱序时按时间序输出(确定性);零窗口也落样本', () => {
    const pkts = [Sw(5, 17520), Sw(2, 65535), Sw(4, 8760), Sw(7, 0), Sw(6, 17520)]
    expect(windowTimeline(pkts).map((s) => s.windowBytes)).toEqual([65535, 8760, 17520, 0])
    expect(windowTimeline(pkts).map((s) => s.time)).toEqual([0.02, 0.04, 0.05, 0.07])
  })

  it('样本数与 computeWindowStats.changes 一致(available 时 = changes + 1)', () => {
    const packets = chain()
    const stats = computeWindowStats(packets)
    const tl = windowTimeline(packets)
    expect(stats.available).toBe(true)
    expect(stats.changes).toBe(3)
    expect(tl).toHaveLength(stats.changes + 1)
  })

  it('随机输入不变量:空输入 available=false;时间单调;窗口值∈[min,max];无相邻重复值;确定性', () => {
    const rand = (n: number) => Math.floor(Math.random() * n)
    for (let trial = 0; trial < 30; trial++) {
      const n = trial % 9
      const pkts = Array.from({ length: n }, (_, i) => P({ number: i + 1, time: rand(100) / 10, tcpWindow: rand(3) === 0 ? undefined : rand(65536) }))
      const stats = computeWindowStats(pkts)
      if (n === 0) {
        expect(stats.available).toBe(false)
        expect(windowTimeline(pkts)).toEqual([])
        continue
      }
      const values = pkts.map((p) => p.tcpWindow).filter((v): v is number => v !== undefined)
      const tl = windowTimeline(pkts)
      if (values.length === 0) {
        expect(stats.available).toBe(false)
        expect(tl).toEqual([])
        continue
      }
      expect(stats.available).toBe(true)
      for (let i = 1; i < tl.length; i++) {
        expect(tl[i]!.time).toBeGreaterThanOrEqual(tl[i - 1]!.time) // 时间单调
        expect(tl[i]!.windowBytes).not.toBe(tl[i - 1]!.windowBytes) // 相邻值必不同
      }
      for (const s of tl) {
        expect(s.windowBytes).toBeGreaterThanOrEqual(Math.min(...values))
        expect(s.windowBytes).toBeLessThanOrEqual(Math.max(...values))
      }
      expect(stats.samples).toBe(values.length)
      expect(stats.changes).toBe(Math.max(0, tl.length - 1))
      expect(JSON.stringify(stats)).toBe(JSON.stringify(computeWindowStats(pkts))) // 确定性
    }
  })
})
