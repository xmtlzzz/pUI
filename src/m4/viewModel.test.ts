import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import { deriveStages } from '../analysis/tcp/stages'
import {
  buildCompareViewModel,
  buildEventSummaries,
  popIn,
  stageAtTime,
  windowProgress,
} from './viewModel'

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

  it('关键报文链只含证据链报文,携带角色标注(不做全量报文列表 —— VDI 数千报文不可用)', () => {
    const role = (n: number) => vm.keyPackets.find((m) => m.packetNumber === n)
    expect(role(6)?.roleBadge).toMatch(/缺口/)
    expect(role(7)?.roleBadge).toMatch(/重复确认|DupACK/)
    expect(role(11)?.roleBadge).toMatch(/重传/)
    expect(role(12)?.roleBadge).toMatch(/恢复/)
    // 关键报文链 = 事件证据链报文(原始段/三个 dupACK/重传/恢复)
    const nums = vm.keyPackets.map((m) => m.packetNumber).sort((a, b) => a - b)
    expect(nums).toEqual([6, 7, 9, 10, 11, 12])
    const gapStageIdx = vm.stages.findIndex((s) => s.label === '缺口显露')
    expect(role(6)?.stageIndex).toBe(gapStageIdx)
  })

  it('序列空间图形数据:Gap hatch 在轴范围内,SACK 块合并去重,已见条如实反映抓包所见', () => {
    const sq = vm.seqSpace
    expect(sq.gaps).toHaveLength(1)
    expect(Math.round(sq.gaps[0][0])).toBe(101)
    expect(Math.round(sq.gaps[0][1])).toBe(201)
    // 已见条如实反映"抓包中见过 0–401 的全部字节":SYN 占 [0,1),数据段
    // 1-101/101-201重传/201-301/301-401 首尾相接连成一段;SACK 报告的 401–501
    // 是对端已收而本抓包未见的字节 —— 不画进已见条,这正是单观察点的体现
    expect(sq.seenRuns).toEqual([[0, 401]])
    // SACK 三块(201-301/201-401/201-501)合并后为一整块 [201,501]
    expect(sq.sackBlocks).toEqual([[201, 501]])
    // ACK 轨迹按时间升序且终点越过缺口
    expect(sq.ackTrack.length).toBeGreaterThan(0)
    expect(sq.retxArrow?.seq).toBe(101) // 重传回补箭头指向重传 seq
    // 刻度落在轴范围内且递增
    for (const t of sq.ticks) {
      expect(t).toBeGreaterThanOrEqual(sq.axisMin)
      expect(t).toBeLessThanOrEqual(sq.axisMax)
    }
  })

  it('事件卡三层完整:观察带包号、推断带置信度、限制非空', () => {
    expect(vm.card.kindLabel).toMatch(/疑似丢包|延迟/)
    expect(vm.card.gapText).toContain('101')
    expect(vm.card.observations.length).toBeGreaterThan(0)
    for (const o of vm.card.observations) {
      expect(o.packetNumber).toBeGreaterThan(0)
      expect(o.statement.length).toBeGreaterThan(0)
    }
    expect(vm.card.inference.confidence).toBeTruthy()
    expect(vm.card.limitations.length).toBeGreaterThan(0)
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
    const retx = vm2!.keyPackets.find((m) => m.packetNumber === 8)
    expect(retx?.roleBadge).toMatch(/冗余重传/)
    // 伪重传场景无缺口:seqSpace.gaps 为空
    expect(vm2!.seqSpace.gaps).toEqual([])
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

describe('buildEventSummaries — 多事件切换器摘要', () => {
  it('保持引擎输出序(未恢复优先),字段与事件一一对应', () => {
    const packets = lossChain()
    // 追加一个缺口外的纯重复重发:#11 已回补缺口,再发一次 seq=201-len100 已见字节
    packets.push(
      c2s({
        number: 13, time: 0.30, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 501, tcpLen: 100,
        tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
      }),
    )
    const facts = analyzeStream(packets)
    const events = detectTcpEvents(facts, packets)
    expect(events.length).toBeGreaterThanOrEqual(2)

    const summaries = buildEventSummaries(events)
    expect(summaries.map((s) => s.id)).toEqual(events.map((e) => e.id))
    // 引擎序:未恢复在前;同为已恢复按证据分排序 —— 摘要层不得重排
    for (let i = 0; i < summaries.length; i++) {
      expect(summaries[i].kindLabel).toBeTruthy()
      expect(summaries[i].severity).toBe(events[i].severity)
      expect(summaries[i].recovered).toBe(events[i].recovered)
      if (events[i].gap) expect(summaries[i].gapText).toContain(`${events[i].gap!.start}`)
      else expect(summaries[i].gapText).toBeUndefined()
    }
    // 缺口类在前(未恢复或证据更完整),伪重传的缺口文案必须为空
    expect(summaries[0].kindLabel).toMatch(/疑似丢包/)
    const spurious = summaries.find((s) => s.kindLabel.includes('冗余'))
    expect(spurious?.gapText).toBeUndefined()
    // 确定性:两次构建逐字节一致
    expect(JSON.stringify(buildEventSummaries(events))).toBe(JSON.stringify(summaries))
  })

  it('空数组返回空数组', () => {
    expect(buildEventSummaries([])).toEqual([])
  })
})

describe('StoryboardMarks — 分镜登场时刻与动画纯函数', () => {
  const packets = lossChain()
  const facts = analyzeStream(packets)
  const event = detectTcpEvents(facts, packets)[0]
  const vm = buildCompareViewModel(packets, facts, event, deriveStages(event, facts, packets))!

  it('缺口链:四个标记齐全、单调有序且归一化在 [0,1]', () => {
    const m = vm.marks
    expect(m.gapRevealAt).toBeDefined()
    expect(m.dupAckWindow).toBeDefined()
    expect(m.retxDrawAt).toBeDefined()
    expect(m.recoverAt).toBeDefined()
    for (const v of [m.gapRevealAt!, m.retxDrawAt!, m.recoverAt!, ...m.dupAckWindow!]) {
      expect(v).toBeGreaterThanOrEqual(0)
      expect(v).toBeLessThanOrEqual(1)
    }
    // 分镜顺序:缺口先显露 → Dup ACK/SACK 窗口 → 重传回补 → 恢复
    expect(m.gapRevealAt!).toBeLessThan(m.dupAckWindow![0])
    expect(m.dupAckWindow![1]).toBeGreaterThanOrEqual(m.retxDrawAt!)
    expect(m.recoverAt!).toBeGreaterThanOrEqual(m.retxDrawAt!)
  })

  it('伪重传链:无缺口标记,重传/恢复标记照常', () => {
    const packets2 = spuriousChain()
    const facts2 = analyzeStream(packets2)
    const ev2 = detectTcpEvents(facts2, packets2)[0]
    const vm2 = buildCompareViewModel(packets2, facts2, ev2, deriveStages(ev2, facts2, packets2))!
    expect(vm2.marks.gapRevealAt).toBeUndefined()
    expect(vm2.marks.dupAckWindow).toBeUndefined()
    expect(vm2.marks.retxDrawAt).toBeDefined()
    expect(vm2.marks.recoverAt).toBeDefined()
  })

  it('windowProgress:线性区间进度,退化区间为阶跃', () => {
    expect(windowProgress(0.1, 0.2, 0.5)).toBe(0)
    expect(windowProgress(0.35, 0.2, 0.5)).toBeCloseTo(0.5)
    expect(windowProgress(0.9, 0.2, 0.5)).toBe(1)
    // 区间退化(起点=终点):早于为 0、到达即为 1
    expect(windowProgress(0.19, 0.2, 0.2)).toBe(0)
    expect(windowProgress(0.21, 0.2, 0.2)).toBe(1)
  })

  it('popIn:淡入 + 单次过冲回落,终态恰为单位缩放', () => {
    const before = popIn(0.1, 0.3)
    expect(before.opacity).toBe(0)
    expect(before.scale).toBeLessThan(1)
    // 中段带过冲(scale > 目标内插值)
    const mid = popIn(0.32, 0.3, 0.05)
    expect(mid.opacity).toBeGreaterThan(0.25)
    expect(mid.scale).toBeGreaterThan(1)
    // 终态稳定
    const end = popIn(0.9, 0.3, 0.05)
    expect(end).toEqual({ opacity: 1, scale: 1 })
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
