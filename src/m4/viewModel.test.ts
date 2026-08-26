import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import { deriveStages } from '../analysis/tcp/stages'
import { buildCompareViewModel, stageAtTime } from './viewModel'

/**
 * M4 对照页视图模型:引擎输出 -> 组件可渲染纯数据。
 * 关键约束来自案例审批记录:阶段带必须由 deriveStages 驱动(不得手写阶段数组);
 * 右栏示意基线绝不含真实包号。
 */

// 场景抓包不经真实 tshark 时无法直接得到 Packet[](scenarios.ts 产出的是 pcapng 字节),
// 这里用与 e2e 测试一致的最小 Packet 构造器按同一剧本手排报文,保证语义等价。
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

/** 与 case-1 剧本一致的完整链 */
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
    tcpSackBlocks: [[201, 501]], tcpDupAckNum: 3, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  c2s({
    number: 11, time: 0.25, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
    tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
  }),
  s2c({ number: 12, time: 0.26, tcpFlags: ACK, tcpSeq: 1, tcpAck: 501, tcpLen: 0, tcpCompleteness: 15 }),
]

const spuriousChain = () => [
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

const buildVM = (packets: Packet[]) => {
  const facts = analyzeStream(packets)
  const events = detectTcpEvents(facts, packets)
  const event = events[0]
  const stages = event ? deriveStages(event, facts, packets) : []
  return buildCompareViewModel(packets, facts, event, stages)
}

describe('buildCompareViewModel', () => {
  const vm = buildVM(lossChain())!

  it('缺口场景产出五个阶段,t0/t1 归一化单调且在 [0,1]', () => {
    expect(vm.stages.map((s) => s.label)).toEqual(['正常传输', '缺口显露', '重复确认与 SACK 增长', '重传回补', '恢复'])
    for (let i = 1; i < vm.stages.length; i++) {
      expect(vm.stages[i].t0).toBeGreaterThanOrEqual(vm.stages[i - 1].t0)
    }
    for (const s of vm.stages) {
      expect(s.t0).toBeGreaterThanOrEqual(0)
      expect(s.t1).toBeLessThanOrEqual(1)
      expect(s.t1).toBeGreaterThanOrEqual(s.t0)
    }
    // 最后一个阶段的结束点应到达时间线末端
    expect(vm.stages[vm.stages.length - 1].t1).toBeCloseTo(1, 5)
  })

  it('关键报文携带角色标注且 stageIndex 正确(阶段联动)', () => {
    const role = (n: number) => vm.leftMessages.find((m) => m.packetNumber === n)
    expect(role(6)?.roleBadge).toMatch(/缺口/)
    expect(role(7)?.roleBadge).toMatch(/重复确认|DupACK/)
    expect(role(11)?.roleBadge).toMatch(/重传/)
    expect(role(12)?.roleBadge).toMatch(/恢复/)
    // 握手报文不在事件时间带内,不进入左栏(左栏聚焦故障过程本身)
    expect(role(3)).toBeUndefined()
    const gapStageIdx = vm.stages.findIndex((s) => s.label === '缺口显露')
    expect(role(6)?.stageIndex).toBe(gapStageIdx)
  })

  it('右栏示意基线不含任何真实包号(数据保真红线)', () => {
    const leftNumbers = new Set(lossChain().map((p) => p.number))
    const texts = vm.referenceSteps.map((r) => `${r.label} ${r.detail}`).join(' ')
    for (const n of leftNumbers) {
      // 步骤文本里不得出现左栏报文号(如 "#6")
      expect(texts).not.toContain(`#${n}`)
    }
    // 且必须是 data/ack 成对的连续步骤
    expect(vm.referenceSteps.length).toBeGreaterThanOrEqual(8)
    expect(vm.referenceSteps.filter((r) => r.kind === 'data').length).toBeGreaterThan(0)
    expect(vm.referenceSteps.filter((r) => r.kind === 'ack').length).toBeGreaterThan(0)
  })

  it('伪重传场景:静默窗阶段入带,角色标注为冗余重传', () => {
    const vm2 = buildVM(spuriousChain())!
    expect(vm2).not.toBeNull()
    expect(vm2!.stages.map((s) => s.label)).toEqual([
      '正常发确',
      '静默窗',
      '冗余重传',
      '确认无变化·已恢复',
    ])
    const retx = vm2!.leftMessages.find((m) => m.packetNumber === 8)
    expect(retx?.roleBadge).toMatch(/冗余重传/)
  })

  it('降级信号从 facts 直通', () => {
    // 正常链全部 false
    expect(vm.degraded).toEqual({
      unorderableInput: false,
      midStream: false,
      lengthUnavailable: false,
      noEvents: false,
    })
    // 无事件 -> null
    const normalPackets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    expect(buildVM(normalPackets)).toBeNull()
  })

  it('确定性:同一输入两次构建完全一致', () => {
    expect(JSON.stringify(buildVM(lossChain()))).toBe(JSON.stringify(buildVM(lossChain())))
  })
})

describe('stageAtTime — 播放时刻到阶段的映射', () => {
  const packets = lossChain()
  const facts = analyzeStream(packets)
  const event = detectTcpEvents(facts, packets)[0]
  const stages = deriveStages(event, facts, packets)
  const vm = buildCompareViewModel(packets, facts, event, stages)!

  it('首阶段开始前返回 -1(阶段带从 0 归一化,仅负时刻/空阶段触发)', () => {
    // 阶段带以首阶段起点归一化为 t0=0,因此时刻 0 已在首阶段内;
    // -1 只出现在空阶段或负时刻
    expect(stageAtTime(vm, -1)).toBe(-1)
  })

  it('落在某阶段区间内返回其索引', () => {
    const expose = vm.stages[1]
    expect(stageAtTime(vm, (expose.t0 + expose.t1) / 2)).toBe(1)
  })

  it('最后阶段结束后停在最后一个索引(终态驻留)', () => {
    expect(stageAtTime(vm, 1)).toBe(vm.stages.length - 1)
    expect(stageAtTime(vm, 2)).toBe(vm.stages.length - 1)
  })
})
