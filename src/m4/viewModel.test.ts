import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import { deriveStages } from '../analysis/tcp/stages'
import {
  buildCompareViewModel,
  buildEventSummaries,
  clipSeqSpaceView,
  popIn,
  severityZh,
  stageAtTime,
  windowProgress,
  zoomStep,
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
    // headline:无缺口事件不再拼出「缺口 无」;严重度以中文呈现
    expect(vm2!.headline).toContain('无缺口')
    expect(vm2!.headline).not.toContain('缺口 无')
    expect(vm2!.headline).toContain('· 低')
  })

  it('伪重传后 ACK 前进:徽标降级为「确认」、阶段标签为「确认前进」(不做无证据断言)', () => {
    const packets = spuriousChain().map((p) =>
      p.number === 9 ? s2c({ number: 9, time: 0.31, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }) : p,
    )
    const vm2 = buildVM(packets)!
    expect(vm2.keyPackets.find((m) => m.packetNumber === 9)?.roleBadge).toBe('确认')
    expect(vm2.stages[vm2.stages.length - 1].label).toBe('确认前进')
  })

  it('双向流(对向字节与缺口区间数值重叠):主视图只画事件方向字节,ACK/SACK 不混入对向 ISN 空间', () => {
    // 旧实现不过滤方向:对向 s2c 的 [101,201) 字节会"填平"c2s 缺口的图形,
    // c2s 自身携带的 ACK 也混进游标造成回跳。这里让两向字节区间数值重叠,
    // 任何混向都会立刻改变图形事实。
    const packets = [
      ...handshake(), // #1 c2s SYN, #2 s2c SYNACK(seq=0), #3 c2s ACK
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 0, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }), // 暴露 c2s 缺口 [101,201)
      s2c({ number: 7, time: 0.06, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 101, tcpLen: 100, tcpCompleteness: 15 }), // 对向数据占同数值区间
      c2s({ number: 8, time: 0.07, tcpFlags: ACK, tcpSeq: 301, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[5100, 5200]], tcpCompleteness: 15 }), // c2s 携带的 SACK 描述对向空间,不得混入
      s2c({ number: 9, time: 0.08, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 201, tcpLen: 100, tcpCompleteness: 15 }),
    ]
    const vmBi = buildVM(packets)!
    const sq = vmBi.seqSpace
    // 缺口仍可见:对向字节不得"填平"事件方向的缺口图形
    expect(sq.gaps).toEqual([[101, 201]])
    // 已见条只含事件方向(c2s)字节:[0,101) ∪ [201,301);混入对向 [101,201) 会连成 [0,301)
    expect(sq.seenRuns).toEqual([
      [0, 101],
      [201, 301],
    ])
    // ACK 游标只认对向(s2c)报文:#2/#5/#7/#9 共 4 条;c2s 自身的 ACK 不混入
    expect(sq.ackTrack).toHaveLength(4)
    // SACK 只收对向报文携带的(描述本方向数据);c2s 携带的 SACK(描述对向空间)不混入
    expect(sq.sackBlocks).toEqual([])
    // 全量缺口如实导出用
    expect(vmBi.allGaps).toEqual([[101, 201]])
  })

  it('方向锚点与分析层一致:流首包为服务端报文时,关键报文链方向不反转', () => {
    // 中途接入常见形态:抓包从服务端报文开始。分析层以流首包源端点为 c2s,
    // 关键报文链必须沿用同一锚点 —— 旧实现自建"首个载荷段"锚点,方向整体反转
    const packets = [
      s2c({ number: 1, time: 0, tcpFlags: ACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 2, time: 0.01, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 0, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
    ]
    const vmMid = buildVM(packets)!
    expect(vmMid).not.toBeNull()
    // 分析层语义:流首包源端点(服务端)= c2s
    const serverKey = `${packets[0].srcIp}:${packets[0].srcPort}`
    for (const k of vmMid.keyPackets) {
      const p = packets.find((q) => q.number === k.packetNumber)!
      expect(k.dir).toBe(`${p.srcIp}:${p.srcPort}` === serverKey ? 'c2s' : 's2c')
    }
  })

  it('低置信乱序以「疑似」进入卡片与 headline;高置信保持「乱序到达」', () => {
    // 模糊区(100ms ≤ 间隔 <200ms 且重复 ACK <3):引擎自述"无法排除确曾丢失"
    const ambiguous = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 8, time: 0.20, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 9, time: 0.21, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    const vmLow = buildVM(ambiguous)!
    expect(vmLow.card.kindLabel).toBe('疑似乱序(迟到补齐)')
    expect(vmLow.headline.startsWith('疑似乱序(迟到补齐)')).toBe(true)

    // 高置信迟到补齐(间隔 20ms):保持断言语气
    const fast = ambiguous.map((p) =>
      p.number === 8
        ? c2s({ number: 8, time: 0.07, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 })
        : p.number === 9
          ? s2c({ number: 9, time: 0.08, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 })
          : p,
    )
    const vmHigh = buildVM(fast)!
    expect(vmHigh.card.kindLabel).toBe('乱序到达')
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

  it('对向序列空间:双向流给出对向静态视图,单向流为 null', () => {
    // lossChain 只有 c2s 数据 → 无对向视图
    expect(vm.opposite).toBeNull()

    // 双向链:服务端也回推数据(s2c ISN=0,SYN 占 1 字节,数据从 seq=1 连续)
    const bi = [
      ...lossChain(),
      s2c({ number: 20, time: 0.27, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 501, tcpLen: 200, tcpCompleteness: 15 }),
      c2s({ number: 21, time: 0.28, tcpFlags: ACK, tcpSeq: 501, tcpAck: 201, tcpLen: 0, tcpCompleteness: 15 }),
    ]
    const vmBi = buildVM(bi)!
    expect(vmBi.opposite).not.toBeNull()
    expect(vmBi.opposite!.dir).toBe('s2c')
    const ov = vmBi.opposite!.view
    expect(ov.seenRuns).toEqual([[1, 201]])
    // 对向无事件聚焦:无重传箭头;刻度/轴自洽
    expect(ov.retxArrow).toBeUndefined()
    for (const t of ov.ticks) {
      expect(t).toBeGreaterThanOrEqual(ov.axisMin)
      expect(t).toBeLessThanOrEqual(ov.axisMax)
    }
    // 对向数据的确认由 c2s 报文携带:ackTrack 含 #21 的 ack=201
    expect(ov.ackTrack.some((a) => a.ack === 201)).toBe(true)
    // 确定性
    expect(JSON.stringify(buildVM(bi)!.opposite)).toBe(JSON.stringify(vmBi.opposite))
  })

  it('区间标注(rangeLabels):已见标"数据",缺口标"未收到";窄区间与确定性受控(M4 用户反馈)', () => {
    const sq = vm.seqSpace
    // 缺口必有标注
    for (const [gs] of sq.gaps) {
      const l = sq.rangeLabels.find((x) => x.kind === 'gap' && x.start === gs)
      expect(l?.text).toBe('未收到')
    }
    // 已见区间标注为"数据"或 SYN/FIN 占位;不超上限;位置升序
    expect(sq.rangeLabels.length).toBeLessThanOrEqual(8)
    for (let i = 1; i < sq.rangeLabels.length; i++) {
      expect(sq.rangeLabels[i].start).toBeGreaterThanOrEqual(sq.rangeLabels[i - 1].start)
    }
    const seenLabels = sq.rangeLabels.filter((l) => l.kind === 'seen')
    expect(seenLabels.every((l) => ['数据', 'SYN', 'FIN'].includes(l.text))).toBe(true)
    // 确定性
    expect(JSON.stringify(buildVM(lossChain())!.seqSpace.rangeLabels)).toBe(JSON.stringify(sq.rangeLabels))
  })

  it('确定性:同一输入两次构建完全一致', () => {
    expect(JSON.stringify(buildVM(lossChain()))).toBe(JSON.stringify(buildVM(lossChain())))
  })

  it('全景视图(M5 完整 SSV):轴覆盖事件方向全部字节,缺口邻域之外的数据如实入图', () => {
    const p = vm.panorama
    expect(p).not.toBeNull()
    // lossChain 的 c2s 数据 [0,401):缺口邻域轴只到 501 附近,全景轴 = 数据实际范围 [0,401]
    expect(p!.axisMin).toBe(0)
    expect(p!.axisMax).toBe(401)
    expect(p!.seenRuns).toEqual([[0, 401]])
    expect(p!.gaps).toEqual([[101, 201]])
    // 缺口邻域中处于轴外的图元,在全景中如实出现(SACK [201,501] 被裁到轴内)
    expect(p!.sackBlocks).toEqual([[201, 401]])
    // 全景区间标注存在且只属于事件方向
    expect(p!.rangeLabels.length).toBeGreaterThan(0)
    // 确定性
    expect(JSON.stringify(buildVM(lossChain())!.panorama)).toBe(JSON.stringify(p))
  })

  it('事件位置轨(M5):证据链报文按序列号位置排布,颜色下标与阶段带一致,位置去重且升序', () => {
    const pins = vm.eventPins
    // lossChain 证据链:缺口显露 #6(seq=201)、重传回补 #11(seq=101)、重复确认 #7-#10(ack=101)、恢复 #12(ack=501)
    expect(pins.length).toBeGreaterThan(0)
    // 按 seq 升序
    for (let i = 1; i < pins.length; i++) {
      expect(pins[i].seq).toBeGreaterThanOrEqual(pins[i - 1].seq)
    }
    // 缺口显露与重传回补是数据段,带长度;重复确认/恢复是 ACK 刻度
    const reveal = pins.find((p) => p.packetNumber === 6)!
    expect(reveal.kind).toBe('data')
    expect(reveal.len).toBe(100)
    const retx = pins.find((p) => p.packetNumber === 11)!
    expect(retx.seq).toBe(101)
    expect(retx.label).toContain('重传回补')
    const dup = pins.find((p) => p.packetNumber === 7)!
    expect(dup.kind).toBe('ack')
    expect(dup.seq).toBe(101)
    // 同位置同类型去重:4 个重复确认 ACK 都在 101 → 只保留 1 个 ack 刻度
    const acks101 = pins.filter((p) => p.kind === 'ack' && p.seq === 101)
    expect(acks101).toHaveLength(1)
    // 颜色下标落在阶段范围:缺口显露 #6 属于阶段 2(下标 1)
    expect(reveal.colorIndex).toBe(1)
    // 确定性
    expect(JSON.stringify(buildVM(lossChain())!.eventPins)).toBe(JSON.stringify(pins))
  })

  it('clipSeqSpaceView:子轴裁剪图元、过滤 ACK 轨迹、刻度按新轴重算(确定性纯函数)', () => {
    const p = vm.panorama!
    const z = clipSeqSpaceView(p, 80, 260)
    expect(z.axisMin).toBe(80)
    expect(z.axisMax).toBe(260)
    // 连续已见区被截断到轴内(lossChain 的已见字节连成 [0,401) 一段)
    expect(z.seenRuns).toEqual([[80, 260]])
    expect(z.gaps).toEqual([[101, 201]])
    // ACK 轨迹按值过滤到窗口内
    for (const a of z.ackTrack) {
      expect(a.ack).toBeGreaterThanOrEqual(80)
      expect(a.ack).toBeLessThanOrEqual(260)
    }
    // 刻度落在新轴内
    for (const t of z.ticks) {
      expect(t).toBeGreaterThanOrEqual(80)
      expect(t).toBeLessThanOrEqual(260)
    }
    // 区间标注钳制到新轴
    for (const l of z.rangeLabels) {
      expect(l.start).toBeGreaterThanOrEqual(80)
      expect(l.end).toBeLessThanOrEqual(260)
    }
    // 完全越界的窗口被钳制回基准轴 → 原样返回(防御);
    // start>end 按归一化处理(与 [min,max] 等价)
    expect(clipSeqSpaceView(p, 500, 600)).toBe(p)
    expect(clipSeqSpaceView(p, 300, 100)).toEqual(clipSeqSpaceView(p, 100, 300))
    // 确定性
    expect(JSON.stringify(clipSeqSpaceView(p, 80, 260))).toBe(JSON.stringify(z))
  })

  it('zoomStep:中心缩放、钳制基准轴、保住最小跨度(纯函数)', () => {
    const base = { axisMin: 0, axisMax: 1000 }
    // 放大:跨度减半(1.6 倍步进),中心不变
    const zin = zoomStep(base, null, 1.6)
    expect(zin.start).toBeGreaterThanOrEqual(0)
    expect(zin.end).toBeLessThanOrEqual(1000)
    expect(zin.end - zin.start).toBeCloseTo(1000 / 1.6, 6)
    expect((zin.start + zin.end) / 2).toBeCloseTo(500, 6)
    // 缩小超出基准轴时钳制回全轴
    const zout = zoomStep(base, zin, 1 / 100)
    expect(zout.start).toBe(0)
    expect(zout.end).toBe(1000)
    // 最小跨度:反复放大不会塌缩到 0(minSpan = max(8, full/1000) = 8)
    let z = zoomStep(base, null, 1.6)
    for (let i = 0; i < 100; i++) z = zoomStep(base, z, 1.6)
    expect(z.end - z.start).toBeCloseTo(8, 6)
    // 偏心窗口放大:中心保持在当前窗口中心
    const z2 = zoomStep(base, { start: 800, end: 1000 }, 1.6)
    expect((z2.start + z2.end) / 2).toBeCloseTo(900, 6)
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
      // 严重度以中文呈现(low/medium/high 枚举不直接面向用户)
      expect(summaries[i].severity).toBe(severityZh(events[i].severity))
      expect(['低', '中', '高']).toContain(summaries[i].severity)
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

  it('阶段带等分布局:阶段按 startTime 排序、等分铺满 [0,1] 无空白(用户反馈:阶段反了/中间空白)', () => {
    const { stages } = vm
    // 顺序:时间单调
    for (let i = 1; i < stages.length; i++) {
      expect(stages[i].startTime).toBeGreaterThanOrEqual(stages[i - 1].startTime)
    }
    // 等分:第 i 阶段占 [i/N, (i+1)/N],首尾相接铺满 [0,1],无重叠无空隙
    stages.forEach((s, i) => {
      expect(s.t0).toBeCloseTo(i / stages.length, 6)
      expect(s.t1).toBeCloseTo((i + 1) / stages.length, 6)
    })
    expect(stages[0].t0).toBe(0)
    expect(stages[stages.length - 1].t1).toBe(1)
    for (let i = 1; i < stages.length; i++) {
      expect(stages[i].t0).toBeCloseTo(stages[i - 1].t1, 8) // 相邻无缝
    }
  })

  it('marks 与阶段带同一等分坐标系:gapRevealAt 落在「缺口显露」阶段区间内', () => {
    const m = vm.marks
    const gapStage = vm.stages.find((s) => s.label === '缺口显露')!
    expect(m.gapRevealAt!).toBeGreaterThanOrEqual(gapStage.t0 - 1e-9)
    expect(m.gapRevealAt!).toBeLessThanOrEqual(gapStage.t1 + 1e-8)
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
