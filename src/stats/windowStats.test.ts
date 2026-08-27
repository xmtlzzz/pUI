import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { computeWindowStats } from './windowStats'

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
