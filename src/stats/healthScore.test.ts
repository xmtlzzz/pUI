import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { computeHealthScore, HEALTH_FORMULA_VERSION } from './healthScore'

/**
 * M5 Health Score(plan M5):透明版本化的会话健康分。
 * 红线(plan 原文):
 * - 仅用于筛选/排序,绝不进入证据、观察或导出;
 * - 公式版本化,扣分明细逐项可见(用户能回答"为什么这个分低");
 * - 覆盖不足(非 TCP/样本不足)显式 unavailable,绝不编造数字。
 */

const P = (o: Partial<Packet> & { number: number; time: number }): Packet =>
  ({ len: 60, transport: 'tcp', proto: 'tcp', direction: 'other', tcpFlags: '0x0010', ...o }) as Packet

const C = (o: Partial<Packet> & { number: number; time: number }) =>
  P({ srcIp: '10.0.0.1', srcPort: 5000, dstIp: '10.0.0.2', dstPort: 80, tcpFlags: '0x0018', tcpLen: 100, ...o })
const S = (o: Partial<Packet> & { number: number; time: number }) =>
  P({ srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 5000, tcpLen: 0, ...o })

/** 健康链:握手 + 8 段数据全被确认 + FIN 关闭 */
function healthyChain(): Packet[] {
  const out: Packet[] = [
    C({ number: 1, time: 0, tcpFlags: '0x0002', tcpLen: 0 }),
    S({ number: 2, time: 0.01, tcpFlags: '0x0012' }),
    C({ number: 3, time: 0.02, tcpFlags: '0x0010', tcpLen: 0 }),
  ]
  let n = 4
  for (let i = 0; i < 8; i++) {
    out.push(C({ number: n++, time: 0.1 + i * 0.1, tcpSeq: 1 + i * 100 }))
    out.push(S({ number: n++, time: 0.11 + i * 0.1, tcpWindow: 65535, tcpAck: 1 + (i + 1) * 100 }))
  }
  out.push(C({ number: n++, time: 10, tcpFlags: '0x0011', tcpLen: 0 })) // FIN·ACK
  out.push(S({ number: n++, time: 10.01, tcpFlags: '0x0011' }))
  return out
}

describe('computeHealthScore — 透明健康分(仅筛选用)', () => {
  it('健康会话:高分且无扣分明细;公式带版本号', () => {
    const h = computeHealthScore(healthyChain())
    expect(h.available).toBe(true)
    expect(h.score).toBeGreaterThanOrEqual(90)
    expect(h.deductions).toHaveLength(0)
    expect(h.formula).toBe(HEALTH_FORMULA_VERSION)
    expect(h.formula).toMatch(/^health-v\d+/)
  })

  it('未恢复缺口扣分最多且明细含规则 key;RST 次之;截断轻微', () => {
    // 未恢复缺口:#5 确认 101 后,#6 直接 seq=401(301–401 从未出现,无确认越过)
    const withHole: Packet[] = [
      C({ number: 1, time: 0, tcpFlags: '0x0002', tcpLen: 0 }),
      S({ number: 2, time: 0.01, tcpFlags: '0x0012' }),
      C({ number: 3, time: 0.02, tcpFlags: '0x0010' }),
      C({ number: 4, time: 0.1, tcpSeq: 1, tcpLen: 100 }),
      S({ number: 5, time: 0.11, tcpAck: 101, tcpWindow: 65535 }),
      C({ number: 6, time: 0.3, tcpSeq: 401, tcpLen: 100 }),
    ]
    const hHole = computeHealthScore(withHole)
    expect(hHole.available).toBe(true)
    expect(hHole.score).toBeLessThanOrEqual(80) // -20/缺口
    const holeDed = hHole.deductions.find((d) => d.key === 'unrecovered-gap')
    expect(holeDed).toBeTruthy()
    expect(holeDed!.points).toBeGreaterThanOrEqual(15)

    // RST:连接被重置(扣分中等)
    const withRst: Packet[] = [
      C({ number: 1, time: 0, tcpFlags: '0x0002', tcpLen: 0 }),
      S({ number: 2, time: 0.01, tcpFlags: '0x0012' }),
      C({ number: 3, time: 0.02 }),
      S({ number: 4, time: 0.5, tcpFlags: '0x0004' }),
    ]
    const hRst = computeHealthScore(withRst)
    expect(hRst.deductions.some((d) => d.key === 'rst')).toBe(true)

    // 截断帧:轻微扣分,扣分值 < 未恢复缺口
    const withTrunc = healthyChain().map((p, i) => (i === 4 ? { ...p, capLen: 54 } : p))
    const hTrunc = computeHealthScore(withTrunc)
    const truncDed = hTrunc.deductions.find((d) => d.key === 'truncated-capture')
    expect(truncDed).toBeTruthy()
    expect((truncDed?.points ?? 99) < (hHole.deductions.find((d) => d.key === 'unrecovered-gap')?.points ?? 0)).toBe(true)
  })

  it('非 TCP 会话 unavailable;同输入两次一致', () => {
    const udp: Packet[] = [{ number: 1, time: 0, len: 60, transport: 'udp', proto: 'dns', direction: 'other' } as Packet]
    expect(computeHealthScore(udp).available).toBe(false)
    expect(computeHealthScore([]).available).toBe(false)
    const h1 = computeHealthScore(healthyChain())
    const h2 = computeHealthScore(healthyChain())
    expect(h2.formula).toBe(HEALTH_FORMULA_VERSION)
    expect(JSON.stringify(h1)).toBe(JSON.stringify(h2))
  })

  it('分数范围 [0,100];扣分合计不超过 100', () => {
    const h = computeHealthScore(healthyChain())
    expect(h.score).toBeDefined()
    expect(h.score!).toBeLessThanOrEqual(100)
    expect(h.score!).toBeGreaterThanOrEqual(0)
    const total = h.deductions.reduce((a, d) => a + d.points, 0)
    expect(h.score! + total).toBe(100) // 满分 100 减扣分明细
  })

  it('缺口阈值:等于 100B 时计为缺口(注释说≥100B,代码用 >= 常量)', () => {
    // ackedTo=0 时,seq=100 的段起点距确认沿恰好 100B:>= 时算缺口,> 时不算。
    const pkts: Packet[] = [
      C({ number: 1, time: 0, tcpFlags: '0x0002', tcpLen: 0 }),
      S({ number: 2, time: 0.01, tcpFlags: '0x0012', tcpAck: 0 }),
      C({ number: 3, time: 0.02, tcpFlags: '0x0010', tcpLen: 0 }),
      C({ number: 4, time: 0.1, tcpSeq: 100, tcpLen: 100 }), // seq=100,len=100
      // 没有推进 ackedTo 的 ACK → 缺口未恢复
    ]
    const h = computeHealthScore(pkts)
    const gap = h.deductions.find((d) => d.key === 'unrecovered-gap')
    expect(gap).toBeTruthy()
    expect(gap!.points).toBe(20)
  })

  it('对向 ACK 字段全缺失:确认沿从不推进,但也不触发缺口(无 ACK 信息无法判断)', () => {
    // 对向(s2c)报文缺少 tcpAck 字段 → ackedTo 始终为 -1,
    // st.ackedTo >= 0 为 false → 不触发缺口判定,分数不受影响。
    const pkts: Packet[] = [
      C({ number: 1, time: 0, tcpFlags: '0x0002', tcpLen: 0 }),
      C({ number: 2, time: 0.1, tcpSeq: 1, tcpLen: 100 }),
      C({ number: 3, time: 0.2, tcpSeq: 501, tcpLen: 100 }), // 明显跳跃,但无 ACK 信息
    ]
    const h = computeHealthScore(pkts)
    // 对向无 tcpAck → 无法确认任何字节,但也不产生缺口(保守:无信息则不扣分)
    const gap = h.deductions.find((d) => d.key === 'unrecovered-gap')
    expect(gap).toBeUndefined()
    // 不应当是负数(回退到 0 分)
    expect(h.available).toBe(true)
    expect(h.score).toBeGreaterThanOrEqual(0)
  })
})
