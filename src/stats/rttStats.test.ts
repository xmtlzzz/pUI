import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { computeRttStats } from './rttStats'

/**
 * M5 RTT 统计:单观察点近似 —— 数据段与其后首个反向 ACK 的间隔。
 * 关键约束(plan M5):样本数不足时 capacity 必须显式 unavailable,绝不编造数字;
 * 措辞是"样本近似",不断言网络往返路径。
 */

const PSHACK = '0x0018'
const ACK = '0x0010'

function pkt(n: number, t: number, dir: 'c2s' | 's2c', extra: Partial<Packet> = {}): Packet {
  const c2s = dir === 'c2s'
  return {
    number: n,
    time: t,
    len: 60,
    transport: 'tcp',
    proto: 'tcp',
    srcIp: c2s ? '10.0.0.1' : '10.0.0.2',
    dstIp: c2s ? '10.0.0.2' : '10.0.0.1',
    srcPort: c2s ? 1234 : 80,
    dstPort: c2s ? 80 : 1234,
    direction: 'other',
    ...extra,
  } as Packet
}

/** 5 个数据段,每个都被对端在 +0.01/+0.02/+0.03/+0.05/+0.08s 确认 */
function sampleChain(): Packet[] {
  const out: Packet[] = []
  let n = 1
  for (let i = 0; i < 5; i++) {
    out.push(pkt(n++, i, 'c2s', { tcpFlags: PSHACK, tcpSeq: 1 + i * 100, tcpLen: 100 }))
    out.push(pkt(n++, i + [0.01, 0.02, 0.03, 0.05, 0.08][i], 's2c', { tcpFlags: ACK, tcpAck: 1 + (i + 1) * 100 }))
  }
  return out
}

describe('computeRttStats — 单观察点 RTT 近似', () => {
  it('产出 p50/p90/max 与样本数,分位数正确', () => {
    const stats = computeRttStats(sampleChain())
    expect(stats.available).toBe(true)
    expect(stats.samples).toBe(5)
    // 样本(ms): 10,20,30,50,80 → p50=30, p90=80(向上取), max=80
    expect(stats.p50Ms).toBe(30)
    expect(stats.p90Ms).toBe(80)
    expect(stats.maxMs).toBe(80)
  })

  it('样本不足(<5)时 available=false,不输出数字(unavailable 语义)', () => {
    const few = sampleChain().slice(0, 4) // 2 个数据段 + 2 ACK
    const stats = computeRttStats(few)
    expect(stats.available).toBe(false)
    expect(stats.samples).toBe(2)
    expect(stats.p50Ms).toBeUndefined()
    expect(stats.p90Ms).toBeUndefined()
    expect(stats.maxMs).toBeUndefined()
  })

  it('纯单向流(无反向 ACK)样本为 0,unavailable', () => {
    const oneWay = [pkt(1, 0, 'c2s', { tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 100 })]
    const stats = computeRttStats(oneWay)
    expect(stats.available).toBe(false)
    expect(stats.samples).toBe(0)
  })

  it('确定性与空输入', () => {
    expect(computeRttStats([]).samples).toBe(0)
    expect(JSON.stringify(computeRttStats(sampleChain()))).toBe(JSON.stringify(computeRttStats(sampleChain())))
  })

  it('重传数据段不重复计入(同流同字节沿只取首个未确认段)——样本为确认事件而非报文', () => {
    const packets = [
      pkt(1, 0, 'c2s', { tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 100 }),
      pkt(2, 0.2, 'c2s', { tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 100 }), // 重传
      pkt(3, 0.3, 's2c', { tcpFlags: ACK, tcpAck: 101 }),
      pkt(4, 0.5, 'c2s', { tcpFlags: PSHACK, tcpSeq: 101, tcpLen: 100 }),
      pkt(5, 0.6, 's2c', { tcpFlags: ACK, tcpAck: 201 }),
      pkt(6, 0.7, 's2c', { tcpFlags: ACK, tcpAck: 301 }),
      pkt(7, 0.8, 's2c', { tcpFlags: ACK, tcpAck: 401 }),
      pkt(8, 0.9, 's2c', { tcpFlags: ACK, tcpAck: 501 }),
    ]
    const stats = computeRttStats(packets)
    expect(stats.samples).toBe(2) // 两次确认事件(#3/#5),重传 #2 不新增样本
    expect(stats.available).toBe(false) // 样本 < MIN_RTT_SAMPLES:重传链本身不足以给出分位数
    expect(stats.maxMs).toBeUndefined()
  })

  it('重传段不覆盖字节沿首次发送时刻(Karn 单观察点:ACK 归属首次发送)', () => {
    // 每个字节沿:首发 t=0 → 重传 t=2(同 seq+len,ACK 尚未越过)→ ACK t=2.5。
    // Karn 语义样本 = ACK − 首次发送 = 2500ms;旧实现重传无条件 set 覆盖 → 500ms。
    const packets: Packet[] = []
    let n = 1
    for (const s of [1, 101, 201, 301, 401]) {
      packets.push(pkt(n++, 0, 'c2s', { tcpFlags: PSHACK, tcpSeq: s, tcpLen: 100 })) // 首发
      packets.push(pkt(n++, 2, 'c2s', { tcpFlags: PSHACK, tcpSeq: s, tcpLen: 100 })) // 重传
    }
    for (const ack of [101, 201, 301, 401, 501]) {
      packets.push(pkt(n++, 2.5, 's2c', { tcpFlags: ACK, tcpAck: ack }))
    }
    const stats = computeRttStats(packets)
    expect(stats.available).toBe(true)
    expect(stats.samples).toBe(5)
    // 全部样本 2500ms:min=p50=p90=max(分位数毫秒粒度,全部相等)
    expect(stats.maxMs).toBe(2500)
    expect(stats.p50Ms).toBe(2500)
  })

  it('畸形 tcpFlags(如 0xGG)解析失败:报文不参与 RST/ACK 分支,不当 0 处理', () => {
    // 旧实现:parseInt('0xGG')=NaN → 0 → 畸形 ACK 报文被静默当作普通 ACK → 产生 100ms 样本。
    // 修复后:flags 无法判定 → 整包跳过,不产生样本也不登记数据。
    const packets = [
      pkt(1, 0, 'c2s', { tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 100 }),
      pkt(2, 0.1, 's2c', { tcpFlags: '0xGG', tcpAck: 101 }),
    ]
    const stats = computeRttStats(packets)
    expect(stats.samples).toBe(0) // 旧实现为 1(畸形 ACK 被当作确认事件)
    expect(stats.available).toBe(false)
  })
})
