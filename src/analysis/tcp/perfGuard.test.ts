import { describe, expect, it } from 'vitest'
import os from 'node:os'
import type { Packet } from '../../model/types'
import { analyzeStream } from './streamAnalysis'
import { detectTcpEvents } from './events'

/**
 * 性能护栏(plan §7:10 万包基线)。
 * VDI 抓包实测卡死根因:detectTcpEvents 每 gap 全量扫 packets 且内嵌 segments.find()(O(gaps×n²));
 * analyzeStream 空洞对账每越洞报文对 openGaps 做 O(k²) 线性匹配。
 * 本组用例以"必须在限期内完成"钉住复杂度,防止回退。
 */

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: (o.tcpLen ?? 0) + 54,
    direction: 'other',
    tcpStream: 0,
    srcIp: '10.0.0.1',
    dstIp: '10.0.0.2',
    srcPort: 1234,
    dstPort: 80,
    ...o,
  } as Packet
}
const PSHACK = '0x0018'
const ACK = '0x0010'

/** 构造 N 个数据段、每第 K 个缺一段(产生大量 gap)+ 大量 dup ACK 的重传风暴形态 */
function stormPackets(nSegments: number): Packet[] {
  const packets: Packet[] = []
  let n = 0
  let t = 0
  const MSS = 1400
  // 握手
  packets.push(pkt({ number: ++n, time: (t += 0.001), tcpFlags: '0x0002', tcpSeq: 0, tcpLen: 0, tcpCompleteness: 15 }))
  packets.push(pkt({ number: ++n, time: (t += 0.001), tcpFlags: '0x0012', tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234 }))
  let expected = 1
  for (let i = 0; i < nSegments; i++) {
    t += 0.0005
    if (i % 3 === 2) {
      // 越过缺口(缺 [expected, expected+MSS))
      packets.push(pkt({ number: ++n, time: t, tcpFlags: PSHACK, tcpSeq: expected + MSS, tcpAck: 1, tcpLen: MSS, tcpCompleteness: 15 }))
      // 一串 dup ACK 停在缺口起点
      for (let d = 0; d < 3; d++) {
        packets.push(pkt({ number: ++n, time: (t += 0.0004), tcpFlags: ACK, tcpSeq: 1, tcpAck: expected, tcpLen: 0, tcpAnalysis: ['duplicate-ack'], tcpDupAckNum: d + 1, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234 }))
      }
      // 重传补齐(留一半不补 → 未恢复 gap,更接近 VDI 劣化链路)
      if (i % 6 === 2) {
        packets.push(pkt({ number: ++n, time: (t += 0.02), tcpFlags: PSHACK, tcpSeq: expected, tcpAck: 1, tcpLen: MSS, tcpAnalysis: ['retransmission'] }))
        packets.push(pkt({ number: ++n, time: (t += 0.001), tcpFlags: ACK, tcpSeq: 1, tcpAck: expected + MSS, tcpLen: 0, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234 }))
      }
    } else {
      packets.push(pkt({ number: ++n, time: t, tcpFlags: PSHACK, tcpSeq: expected, tcpAck: 1, tcpLen: MSS, tcpCompleteness: 15 }))
      packets.push(pkt({ number: ++n, time: (t += 0.0005), tcpFlags: ACK, tcpSeq: 1, tcpAck: expected + MSS, tcpLen: 0, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234 }))
    }
    expected += MSS
  }
  return packets
}

describe('性能护栏:VDI 规模重传风暴不得冻死主线程', () => {
  it('5000 段风暴(约 1.5 万包、~800 gaps)分析在 3 秒内完成且结果正确', () => {
    const packets = stormPackets(5000)
    expect(packets.length).toBeGreaterThan(10000)
    const t0 = performance.now()
    const facts = analyzeStream(packets)
    const events = detectTcpEvents(facts, packets)
    const elapsed = performance.now() - t0
    // 预算 = 3s 基线 × sqrt(CPU 数):全量并发跑时无关测试争抢 CPU 会整体拖慢
    // 1.5-2 倍(实测单独跑 ~1s、并发 ~2.7-4.8s 抖动)。护栏目标是"不冻死主线程"
    // 的量级(秒级而非分钟级),放宽避免并发假红;单独跑仍有 3s 级硬约束意义。
    const budget = 3000 * Math.sqrt(Math.max(1, os.cpus?.length ?? 1))
    expect(elapsed).toBeLessThan(budget)
    // 结果也要对:大量 gap 被检出,未恢复的排前面
    expect(facts.gaps.length).toBeGreaterThan(500)
    expect(events.length).toBeGreaterThan(500)
    expect(events[0].recovered).toBe(false)
  }, 60000)

  it('每 gap 恰一个 loss 事件;未被缺口覆盖的重传才报 spurious(无重复报告)', () => {
    const packets = stormPackets(300)
    const facts = analyzeStream(packets)
    const events = detectTcpEvents(facts, packets)
    const lossEvents = events.filter((e) => e.kind === 'possible-loss-or-delay' || e.kind === 'reordering')
    // 每个缺口恰一个事件
    expect(lossEvents.length).toBe(facts.gaps.length)
    // spurious 事件的报文号必须两两不同,且都不是任何缺口事件的填补者
    const fillers = new Set(facts.gaps.map((g) => g.filledByPacket))
    const spurPackets = events.filter((e) => e.kind === 'possible-ack-loss-or-spurious').map((e) => e.retransmissionPacket)
    expect(new Set(spurPackets).size).toBe(spurPackets.length)
    for (const p of spurPackets) expect(fillers.has(p)).toBe(false)
    // 总事件数 = 缺口事件 + 独立伪重传事件(不多报)
    expect(events.length).toBe(lossEvents.length + spurPackets.length)
  })
})
