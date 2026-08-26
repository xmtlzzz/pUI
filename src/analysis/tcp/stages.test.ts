import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import { analyzeStream } from './streamAnalysis'
import { detectTcpEvents } from './events'
import { deriveStages } from './stages'

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: (o.tcpLen ?? 0) + 54,
    direction: 'other',
    tcpStream: 0,
    ...o,
  } as Packet
}
const c2s = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
const s2c = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })

const SYN = '0x0002'
const SYNACK = '0x0012'
const ACK = '0x0010'
const PSHACK = '0x0018'

const handshake = () => [
  c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0, tcpCompleteness: 15 }),
  s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15 }),
  c2s({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15 }),
]

const run = (packets: Packet[]) => ({ facts: analyzeStream(packets), packets })

/** case-1 场景:Gap + DupACK×3 + SACK 增长 + 重传 + 恢复 */
const lossChain = () => [
  ...handshake(),
  c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
  c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({
    number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 301]], tcpDupAckNum: 1, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  c2s({ number: 8, time: 0.07, tcpFlags: PSHACK, tcpSeq: 301, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({
    number: 9, time: 0.08, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 401]], tcpDupAckNum: 2, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  s2c({
    number: 10, time: 0.09, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 401]], tcpDupAckNum: 3, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  c2s({
    number: 11, time: 0.25, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
    tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
  }),
  s2c({ number: 12, time: 0.26, tcpFlags: ACK, tcpSeq: 1, tcpAck: 401, tcpLen: 0, tcpCompleteness: 15 }),
]

describe('deriveStages — 故障阶段推导(审批强化要求:阶段标注)', () => {
  it('case-1 完整链划分为五个命名阶段,边界与报文号正确', () => {
    const { facts, packets } = run(lossChain())
    const evs = detectTcpEvents(facts, packets)
    const stages = deriveStages(evs[0], facts, packets)
    expect(stages.map((s) => s.label)).toEqual([
      '正常传输',
      '缺口显露',
      '重复确认与 SACK 增长',
      '重传回补',
      '恢复',
    ])
    // 每阶段的起止报文号(闭区间)与时刻
    expect(stages.map((s) => [s.fromPacket, s.toPacket])).toEqual([
      [4, 5],
      [6, 6],
      [7, 10],
      [11, 11],
      [12, 12],
    ])
    expect(stages[0].startTime).toBe(0.03)
    expect(stages[4].endTime).toBe(0.26)
  })

  it('每阶段携带信息要点,故障阶段必须带证据引用(不允许只有名字)', () => {
    const { facts, packets } = run(lossChain())
    const stages = deriveStages(detectTcpEvents(facts, packets)[0], facts, packets)
    for (const s of stages) {
      expect(s.summary.length).toBeGreaterThan(0)
    }
    // 背景对照阶段(正常传输)没有对应观察,refs 允许为空;
    // 但故障阶段(缺口显露/重复确认/重传回补/恢复)必须能指回真实观察
    const faultStages = stages.filter((s) => s.label !== '正常传输')
    expect(faultStages.length).toBeGreaterThan(0)
    for (const s of faultStages) {
      expect(s.observationRefs.length).toBeGreaterThan(0)
    }
    // 缺口显露阶段的信息要点必须包含缺口事实
    expect(stages[1].summary).toMatch(/缺口|101/)
    // 重传回补阶段必须指向填补报文
    expect(stages[3].summary).toMatch(/#11|重发/)
    expect(stages[3].observationRefs.length).toBeGreaterThan(0)
  })

  it('阶段时间连续且单调递增(可作播放轨道)', () => {
    const { facts, packets } = run(lossChain())
    const stages = deriveStages(detectTcpEvents(facts, packets)[0], facts, packets)
    for (let i = 1; i < stages.length; i++) {
      expect(stages[i].startTime).toBeGreaterThanOrEqual(stages[i - 1].startTime)
    }
    for (const s of stages) {
      expect(s.endTime).toBeGreaterThanOrEqual(s.startTime)
    }
  })

  it('case-2 乱序场景:迟到补齐阶段标注「标签对峙」要点', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({
        number: 7, time: 0.052, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
      }),
      s2c({ number: 8, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    const { facts } = run(packets)
    const stages = deriveStages(detectTcpEvents(facts, packets)[0], facts, packets)
    // 阶段名体现"乱序"语义而非丢包
    expect(stages.some((s) => /乱序|迟到/.test(s.label))).toBe(true)
    // 对峙要点:tshark 标签作为观察出现
    const allSummary = stages.map((s) => s.summary).join(' ')
    expect(allSummary).toMatch(/tshark|标签/)
  })

  it('case-3 伪重传场景:静默窗成为显式阶段', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 201, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({
        number: 8, time: 0.30, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission', 'spurious-retransmission'], tcpCompleteness: 15,
      }),
      s2c({ number: 9, time: 0.31, tcpFlags: ACK, tcpSeq: 1, tcpAck: 201, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    const { facts } = run(packets)
    const evs = detectTcpEvents(facts, packets)
    const stages = deriveStages(evs[0], facts, packets)
    // 静默窗必须是显式阶段(审批要求:静默本身是证据)
    expect(stages.some((s) => /静默/.test(s.label))).toBe(true)
    expect(stages.map((s) => s.label)).toEqual([
      '正常发确',
      '静默窗',
      '冗余重传',
      '确认无变化·已恢复',
    ])
  })

  it('确定性:同一输入两次推导完全一致', () => {
    const build = () => {
      const packets = lossChain()
      const facts = analyzeStream(packets)
      const evs = detectTcpEvents(facts, packets)
      return deriveStages(evs[0], facts, packets)
    }
    expect(JSON.stringify(build())).toBe(JSON.stringify(build()))
  })

  it('空事件时返回空数组(无可对照事件就没有阶段)', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    const { facts } = run(packets)
    expect(deriveStages(undefined, facts, packets)).toEqual([])
  })
})
