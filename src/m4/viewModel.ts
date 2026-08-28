import type { Packet } from '../model/types'
import type { StreamAnalysisFacts, StreamDirection } from '../analysis/tcp/streamAnalysis'
import type { TcpEvent } from '../analysis/tcp/events'
import type { EventStage } from '../analysis/tcp/stages'

/**
 * M4 故障/正常对照页的视图模型层:把引擎输出投影为组件可直接渲染的纯数据。
 *
 * 设计约束(来自案例审批记录,docs/specs/m4-cases/*):
 * - 阶段带必须由 deriveStages 的输出驱动,本层只做坐标归一化与报文-阶段关联,
 *   绝不在组件里手写阶段数组;
 * - 右栏「正常参考」是解释性示意,本层生成的 referenceSteps 不含任何真实包号
 *   (数据保真红线,有测试钉住);
 * - 纯函数、确定性输出,同一输入两次构建结果逐字节一致。
 */

/** 对照页左栏消息(真实抓包报文 + 事件角色标注) */
export interface CompareMessage {
  packetNumber: number
  time: number
  dir: 'c2s' | 's2c'
  /** 展示标签,如 "PSH·ACK seq=201 len=100" */
  label: string
  flags?: string
  seq?: number
  ack?: number
  len?: number
  sackBlocks?: Array<[number, number]>
  /** tshark 标签(仅作观察展示,不参与渲染判定) */
  tags?: string[]
  /** 所属阶段索引(-1 = 不属于任何阶段);播放高亮联动用 */
  stageIndex: number
  /** 事件角色标注(缺口显露/重复确认/重传回补/恢复 等),直接渲染在报文旁 */
  roleBadge?: string
}

/** 右栏示意基线的一个步骤(绝不含真实包号) */
export interface ReferenceStep {
  index: number
  label: string
  kind: 'data' | 'ack'
  detail: string
}

/** 序列空间图形(案例文档承诺的核心可视化)所需的纯数据 */
export interface SeqSpaceView {
  axisMin: number
  axisMax: number
  ticks: number[]
  /** 已见字节连续段(合并后,裁剪到坐标轴范围) */
  seenRuns: Array<[number, number]>
  /** 缺口区间(hatch 渲染) */
  gaps: Array<[number, number]>
  /** SACK 块(合并去重后,裁剪到坐标轴范围,上限 100 块) */
  sackBlocks: Array<[number, number]>
  /** ACK 轨迹(按时间升序):ACK 游标随播放时刻推进 */
  ackTrack: Array<{ time: number; ack: number }>
  retxArrow?: { seq: number }
  /**
   * 区间标注(M4 用户反馈):每个已见/SACK 区间的简短报文类型标签,如
   * "ack"/"数据"/"req"。只标注**代表性区间**(首尾 + 最宽若干个,上限 8 个),
   * 避免标注过密;渲染时可按宽度丢弃放不下的。
   */
  rangeLabels: Array<{ start: number; end: number; text: string; kind: 'seen' | 'gap' }>
}

/** 事件卡:观察/推断/限制分层(案例文档要求三层固定可见) */
export interface EventCard {
  kindLabel: string
  severity: string
  recovered: boolean
  gapText?: string
  observations: Array<{ packetNumber: number; statement: string }>
  inference: { statement: string; confidence: string }
  limitations: string[]
}

/** 阶段带轨道条目:EventStage + 归一化时间坐标 */
export interface StageBandEntry extends EventStage {
  /** 相对事件时间线的归一化起点/终点 [0,1],供阶段带布局 */
  t0: number
  t1: number
}

export interface CompareViewModel {
  /** 事件卡(观察/推断/限制分层) */
  card: EventCard
  /** 序列空间图形化(左栏核心可视化,替代逐报文列表) */
  seqSpace: SeqSpaceView
  /** 关键报文链(chips):只放事件证据链上的报文,不是全量报文 */
  keyPackets: CompareMessage[]
  stages: StageBandEntry[]
  referenceSteps: ReferenceStep[]
  /** 分镜标记:序列空间图形各元素的登场时刻(见 StoryboardMarks) */
  marks: StoryboardMarks
  /** 当前事件的数据方向(c2s/s2c),供对向切换器展示 */
  direction: StreamDirection
  /** 对向序列空间:双向流中事件方向之外那一侧的字节空间;对向无数据时为 null */
  opposite: { dir: StreamDirection; view: SeqSpaceView } | null
  degraded: {
    unorderableInput: boolean
    midStream: boolean
    lengthUnavailable: boolean
    noEvents: boolean
  }
  headline: string
}

/** 左栏顶部事件切换器的条目(轻量摘要;完整卡片在选中后由 buildCompareViewModel 生成) */
export interface CompareEventSummary {
  /** 引擎的确定性事件 id,作为切换器的稳定 key */
  id: string
  kindLabel: string
  severity: string
  recovered: boolean
  /** 缺口范围文案;伪重传类无缺口为 undefined */
  gapText?: string
  startTime: number
  endTime: number
}

/** 事件的缺口范围文案(headline 与事件列表共用同一措辞) */
export function gapTextOf(event: TcpEvent): string | undefined {
  return event.gap ? `${event.gap.start}–${event.gap.end}(${event.gap.byteCount}B)` : undefined
}

/**
 * 把引擎事件数组投影为切换器摘要。顺序保持引擎输出序
 * (未恢复优先 → 证据完整度 → 时长),不做二次排序 —— 排序语义只在一处定义。
 */
export function buildEventSummaries(events: TcpEvent[]): CompareEventSummary[] {
  return events.map((e) => ({
    id: e.id,
    kindLabel: KIND_LABEL[e.kind],
    severity: e.severity,
    recovered: e.recovered,
    gapText: gapTextOf(e),
    startTime: e.startTime,
    endTime: e.endTime,
  }))
}

/**
 * 分镜标记:证据链关键报文的登场时刻(归一化到阶段带时间轴 [0,1],与 StageBandEntry.t0/t1 同坐标系)。
 * 组件据此按播放时刻声明式推进各元素 appearance —— 动画不承载唯一信息,
 * 静态模式直接渲染全部元素(信息等价,审批约束 #4)。
 */
export interface StoryboardMarks {
  /** Gap hatch 显露时刻(越过缺口的报文到达) */
  gapRevealAt?: number
  /** Dup ACK / SACK 窗口:SACK 块在 [start,end] 内逐块长出 */
  dupAckWindow?: [number, number]
  /** 重传回补箭头画出时刻 */
  retxDrawAt?: number
  /** 恢复确认落点(ACK 游标闪现脉冲的时刻) */
  recoverAt?: number
}

/** [start,end] 区间的线性进度,t 早于 start 为 0、晚于 end 为 1;区间退化时视为阶跃 */
export function windowProgress(t: number, start: number, end: number): number {
  const d = end - start
  if (d <= 1e-9) return t >= end ? 1 : 0
  return Math.min(1, Math.max(0, (t - start) / d))
}

/**
 * 登场弹跳:[at, at+dur] 内不透明度线性升起,幅度带一次衰减过冲(sin 弹性),
 * 结束后停在 1。确定性纯函数 —— 同一时刻永远得到同一形状。
 */
export function popIn(
  t: number,
  at: number,
  dur = 0.05,
): { opacity: number; scale: number } {
  if (t < at) return { opacity: 0, scale: 0.85 }
  const p = windowProgress(t, at, at + dur)
  if (p >= 1) return { opacity: 1, scale: 1 }
  // opacity 随进度升起;scale 在中段冲到 ~1.12 再回落(过冲幅度随 p² 衰减)
  const overshoot = Math.sin(p * Math.PI) * 0.12 * (1 - p * 0.35)
  return { opacity: 0.25 + 0.75 * p, scale: 0.85 + 0.15 * p + overshoot }
}

const KIND_LABEL: Record<TcpEvent['kind'], string> = {
  'possible-loss-or-delay': '疑似丢包 / 延迟到达',
  reordering: '乱序到达',
  'possible-ack-loss-or-spurious': '疑似 ACK 丢失 / 冗余重传',
}

function flagsLabel(flagsHex: string | undefined): string {
  if (!flagsHex) return ''
  const n = Number.parseInt(flagsHex, 16)
  if (Number.isNaN(n)) return ''
  const parts: string[] = []
  if (n & 0x01) parts.push('FIN')
  if (n & 0x02) parts.push('SYN')
  if (n & 0x04) parts.push('RST')
  if (n & 0x08) parts.push('PSH')
  if (n & 0x10) parts.push('ACK')
  return parts.join('·')
}

/** 报文的展示方向:以流内首个数据报文源端点为 c2s(与分析层 dirOf 一致的近似) */
function directionOf(p: Packet, c2sKey: string | null): 'c2s' | 's2c' {
  if (!c2sKey) return p.srcPort != null && p.dstPort != null && p.srcPort < p.dstPort ? 'c2s' : 's2c'
  return `${p.srcIp ?? '?'}:${p.srcPort ?? 0}` === c2sKey ? 'c2s' : 's2c'
}

/**
 * 从事件的证据结构推断报文的事件角色(渲染在报文旁的醒目标注)。
 * 依据是 detectTcpEvents 输出的确定性字段(packet 相等性),不是对文本的猜测。
 */
function roleBadgeOf(packetNumber: number, event: TcpEvent): string | undefined {
  if (event.originalSegmentPacket === packetNumber && event.gap) return '缺口显露'
  if (event.retransmissionPacket === packetNumber) {
    return event.kind === 'reordering' ? '迟到补齐' : event.gap ? '重传回补' : '冗余重传'
  }
  if (event.recoveryAckPacket === packetNumber) {
    return event.kind === 'possible-ack-loss-or-spurious' ? '确认无变化' : '恢复'
  }
  if (event.duplicateAckPackets.includes(packetNumber)) return `重复确认 ×${event.duplicateAckCount}`
  return undefined
}

/** 右栏示意基线:固定 5 段连续发送 + 每段被立即确认(形状取自 reference-normal,不含包号) */
function buildReferenceSteps(): ReferenceStep[] {
  const steps: ReferenceStep[] = []
  for (let i = 1; i <= 5; i++) {
    steps.push({
      index: i,
      label: `数据段 ${i} · 100B`,
      kind: 'data',
      detail: '按序列顺序连续发送',
    })
    steps.push({
      index: i,
      label: `ACK 前进到 ${i * 100 + 1}`,
      kind: 'ack',
      detail: '每个数据段都被立即确认,累计 ACK 单调前进,无停滞',
    })
  }
  return steps
}

/**
 * 构建对照页视图模型。无可对照事件时返回 null(调用方渲染空态)。
 */
export function buildCompareViewModel(
  packets: Packet[],
  facts: StreamAnalysisFacts,
  event: TcpEvent | undefined,
  stages: EventStage[],
): CompareViewModel | null {
  if (!event || stages.length === 0) return null

  // c2s 锚点:首个数据段源端点(facts.segments 已带 direction,直接取第一个非零载荷段的)
  const firstSeg = facts.segments.find((s) => s.seqLen > 0)
  const firstPkt = firstSeg ? packets.find((p) => p.number === firstSeg.packetNumber) : undefined
  const c2sKey = firstPkt ? `${firstPkt.srcIp ?? '?'}:${firstPkt.srcPort ?? 0}` : null

  // 阶段带布局:按 startTime 稳定排序(防御 derive 顺序与时间倒挂,用户反馈"阶段反了"),
  // 并**均匀等分**每个阶段占 1/N —— 阶段是离散事件点(真实时间跨度常为零),按真实时间
  // 归一化会让多数阶段挤在两端、中间大片空白(用户反馈)。DSH 式进度条按分镜顺序连续铺满
  // 更符合"过程感";真实时间仍由 startTime/endTime 与播放游标承载。
  const sorted = [...stages].sort((a, b) => a.startTime - b.startTime || a.fromPacket - b.fromPacket)
  const N = Math.max(sorted.length, 1)
  const bandStages: StageBandEntry[] = sorted.map((s, i) => ({
    ...s,
    t0: i / N,
    t1: (i + 1) / N,
  }))

  // ---- 关键报文链:只取事件证据链上的报文(不是全量报文 —— VDI 抓包逐报文列表不可用) ----
  const keyNumbers = new Set<number>()
  if (event.originalSegmentPacket != null) keyNumbers.add(event.originalSegmentPacket)
  if (event.retransmissionPacket != null) keyNumbers.add(event.retransmissionPacket)
  if (event.recoveryAckPacket != null) keyNumbers.add(event.recoveryAckPacket)
  for (const n of event.duplicateAckPackets) keyNumbers.add(n)
  const keyPackets: CompareMessage[] = packets
    .filter((p) => keyNumbers.has(p.number))
    .sort((a, b) => a.time - b.time || a.number - b.number)
    .map((p) => {
      const stageIdx = bandStages.findIndex((s) => p.time >= s.startTime && p.time <= s.endTime)
      const fl = flagsLabel(p.tcpFlags)
      const labelParts = [fl, p.tcpSeq != null ? `seq=${p.tcpSeq}` : null, p.tcpLen ? `len=${p.tcpLen}` : null].filter(Boolean)
      return {
        packetNumber: p.number,
        time: p.time,
        dir: directionOf(p, c2sKey),
        label: labelParts.join(' ') || 'TCP',
        flags: p.tcpFlags,
        seq: p.tcpSeq,
        ack: p.tcpAck,
        len: p.tcpLen,
        sackBlocks: p.tcpSackBlocks,
        tags: p.tcpAnalysis,
        stageIndex: stageIdx,
        roleBadge: roleBadgeOf(p.number, event),
      }
    })

  // ---- 序列空间图形化(案例文档核心承诺):已见字节条 + Gap hatch + SACK 块 + ACK 轨迹 ----
  const retxPkt = event.retransmissionPacket != null ? packets.find((p) => p.number === event.retransmissionPacket) : undefined
  const seqSpace = buildSeqSpaceView(facts, packets, event, retxPkt?.tcpSeq)
  // 对向视图(双向流):事件方向之外那一侧的静态字节空间
  const opposite = buildOppositeSeqSpaceView(facts, packets, event)

  const card: EventCard = {
    kindLabel: KIND_LABEL[event.kind],
    severity: event.severity,
    recovered: event.recovered,
    gapText: gapTextOf(event),
    observations: event.observations.map((o) => ({ packetNumber: o.packetNumber, statement: o.statement })),
    inference: { statement: event.inference.statement, confidence: event.inference.confidence },
    limitations: event.limitations,
  }

  // ---- 分镜标记:证据链报文时刻 -> 阶段带等分坐标(与 bandStages 同一坐标系) ----
  // 阶段是离散点,按真实时间全局归一化会错位;改为把时刻映射到"它所属阶段"的
  // 等分区间内(阶段内按真实时间比例),使动画与阶段带、播放游标对齐。
  const timeToBand = (t: number): number | undefined => {
    const idx = bandStages.findIndex((s) => t >= s.startTime && t <= s.endTime)
    if (idx < 0) return undefined
    const seg = bandStages[idx]
    const segSpan = seg.endTime - seg.startTime
    const frac = segSpan > 0 ? (t - seg.startTime) / segSpan : 0
    return seg.t0 + frac * (seg.t1 - seg.t0)
  }
  const timeOfPacket = (n: number | undefined): number | undefined => {
    if (n == null) return undefined
    const p = packets.find((q) => q.number === n)
    return p ? timeToBand(p.time) : undefined
  }
  const marks: StoryboardMarks = {
    gapRevealAt: timeOfPacket(event.originalSegmentPacket),
    retxDrawAt: timeOfPacket(event.retransmissionPacket),
    recoverAt: timeOfPacket(event.recoveryAckPacket),
  }
  if (event.duplicateAckPackets.length > 0) {
    // SACK 增长窗口:首个 Dup ACK -> 缺口被回补/恢复之前的时间段。
    // 窗口终点取证据链上可用时刻的最大值(重传或恢复),不臆造引擎之外的端点
    const w0 = timeOfPacket(event.duplicateAckPackets[0])
    const candTimes = [event.retransmissionPacket, event.recoveryAckPacket]
      .map((n) => (n != null ? packets.find((q) => q.number === n)?.time : undefined))
      .filter((t): t is number => t != null)
    const w1Raw = candTimes.length > 0 ? Math.max(...candTimes) : stages[stages.length - 1]?.endTime
    const w1 = w1Raw != null ? timeToBand(w1Raw) : undefined
    if (w0 != null && w1 != null && w1 >= w0) marks.dupAckWindow = [w0, w1]
  }

  const gap = gapTextOf(event) ?? '无'
  return {
    card,
    seqSpace,
    keyPackets,
    stages: bandStages,
    referenceSteps: buildReferenceSteps(),
    marks,
    direction: event.direction,
    opposite,
    degraded: {
      unorderableInput: facts.unorderableInput,
      midStream: facts.midStream,
      lengthUnavailable: facts.lengthUnavailable,
      noEvents: false,
    },
    headline: `${KIND_LABEL[event.kind]} · 缺口 ${gap} · ${event.severity}`,
  }
}

/** SACK 块合并:重叠/相邻合并,控制渲染块数 */
function mergeRanges(ranges: Array<[number, number]>): Array<[number, number]> {
  if (ranges.length === 0) return []
  const sorted = [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const out: Array<[number, number]> = [sorted[0]]
  for (let i = 1; i < sorted.length; i++) {
    const last = out[out.length - 1]
    if (sorted[i][0] <= last[1]) last[1] = Math.max(last[1], sorted[i][1])
    else out.push(sorted[i])
  }
  return out
}

const SEQ_VIEW_MAX_SACK = 100 // 渲染护栏:超过则截断(极端抓包的 SACK 风暴不拖垮 DOM)

/** 刻度:1/2/5 整步长(与案例文档 1…501 风格一致) */
function ticksFor(axisMin: number, axisMax: number): number[] {
  const rawStep = (axisMax - axisMin) / 5
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)))
  const norm = rawStep / mag
  const step = (norm >= 5 ? 5 : norm >= 2 ? 2 : 1) * mag
  const ticks: number[] = []
  for (let t = Math.ceil(axisMin / step) * step; t <= axisMax; t += step) ticks.push(t)
  return ticks
}

/** 构建序列空间图形数据:坐标轴聚焦缺口邻域 */
function buildSeqSpaceView(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  event: TcpEvent,
  retxSeq: number | undefined,
): SeqSpaceView {
  // 轴范围:以缺口为中心,前后各留缺口宽度的 3 倍(最小 100B)——缺口约占轴的 1/6,
  // 既醒目又能把邻域已见数据与 SACK 块(缺口后已到达的数据)一起画进来;
  // 伪重传场景无缺口,以重传 seq 为中心取固定窗口
  let a0: number
  let a1: number
  let pad: number
  if (event.gap) {
    a0 = event.gap.start
    a1 = event.gap.end
    pad = Math.max(event.gap.byteCount, 100) * 3
  } else {
    a0 = retxSeq ?? 0
    a1 = a0 + 100
    pad = 300
  }
  const axisMin = Math.max(0, a0 - pad)
  const axisMax = a1 + pad

  const clip = ([s, e]: [number, number]): [number, number] | null =>
    e <= axisMin || s >= axisMax ? null : [Math.max(s, axisMin), Math.min(e, axisMax)]

  // 已见字节:从 facts 的段分类重建(有载荷的段按 seq+len 并入;用简单合并,数量有限)
  const seenRaw: Array<[number, number]> = []
  for (const seg of facts.segments) {
    if (seg.seqLen <= 0) continue
    seenRaw.push([seg.seq, (seg.seq + seg.seqLen) >>> 0])
  }
  const seenRuns = mergeRanges(seenRaw)
    .map(clip)
    .filter((r): r is [number, number] => r != null)

  const gaps = facts.gaps
    .map((g) => clip([g.start, g.end]))
    .filter((r): r is [number, number] => r != null)

  const sackRaw: Array<[number, number]> = []
  for (const p of packets) for (const b of p.tcpSackBlocks ?? []) sackRaw.push(b)
  const sackBlocks = mergeRanges(sackRaw)
    .map(clip)
    .filter((r): r is [number, number] => r != null)
    .slice(0, SEQ_VIEW_MAX_SACK)

  // ACK 轨迹:反向报文的 (time, ack) 序列,裁剪到轴范围附近
  const ackTrack = packets
    .filter((p) => p.tcpAck != null)
    .sort((x, y) => x.time - y.time)
    .map((p) => ({ time: p.time, ack: p.tcpAck! }))

  // 刻度:1/2/5 整步长(与案例文档 1…501 风格一致)
  const ticks = ticksFor(axisMin, axisMax)

  return {
    axisMin,
    axisMax,
    ticks,
    seenRuns,
    gaps,
    sackBlocks,
    ackTrack,
    retxArrow: retxSeq != null ? { seq: retxSeq } : undefined,
    rangeLabels: buildRangeLabels(facts, packets, seenRuns, gaps, axisMin, axisMax),
  }
}

/** 区间标注上限:按宽度优先保留(防拥挤,用户反馈"标注不能太挤") */
export const RANGE_LABEL_MAX = 8

/**
 * 区间标注(M4 用户反馈):给序列空间的每个区间一个简短的类型标签 ——
 * 已见区间标"数据"(代表段有载荷)或 "SYN"/"FIN"(仅握手占位),缺口标"未收到"。
 * 过窄(轴宽 1.5% 以下)的区间放不下文字,不标注;超过上限按宽度优先保留。
 */
function buildRangeLabels(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  seenRuns: Array<[number, number]>,
  gaps: Array<[number, number]>,
  axisMin: number,
  axisMax: number,
): SeqSpaceView['rangeLabels'] {
  const axisSpan = axisMax - axisMin
  const labels: SeqSpaceView['rangeLabels'] = []
  for (const [s, e] of seenRuns) {
    labels.push({ start: s, end: e, text: seenRunLabel(facts, packets, s, e), kind: 'seen' })
  }
  for (const [s, e] of gaps) {
    labels.push({ start: s, end: e, text: '未收到', kind: 'gap' })
  }
  return labels
    .filter((l) => l.end - l.start >= axisSpan * 0.015)
    .sort((a, b) => b.end - b.start - (a.end - a.start)) // 宽的优先保留
    .slice(0, RANGE_LABEL_MAX)
    .sort((a, b) => a.start - b.start) // 输出按位置升序
}

/** 已见区间的代表标签:覆盖区间中点的段有载荷 → "数据";仅 SYN/FIN 占位 → 对应名 */
function seenRunLabel(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  s: number,
  e: number,
): string {
  const mid = s + Math.floor((e - s) / 2)
  for (const seg of facts.segments) {
    if (seg.seqLen <= 0) continue
    const end = (seg.seq + seg.seqLen) >>> 0
    if (seg.seq <= mid && mid < end) {
      const p = packets.find((q) => q.number === seg.packetNumber)
      if (p && (p.tcpLen ?? 0) > 0) return '数据'
      const f = Number.parseInt(p?.tcpFlags ?? '', 16)
      if (!Number.isNaN(f) && f & 0x02) return 'SYN'
      if (!Number.isNaN(f) && f & 0x01) return 'FIN'
      return '数据'
    }
  }
  return '数据'
}

/**
 * 对向序列空间(M4 收尾项):双向流中,事件方向之外那一侧的数据字节空间。
 * 静态事实视图 —— 无事件聚焦、无分镜动画(对向没有可解释事件的证据链)。
 * 轴覆盖对向全部数据范围;SACK/ACK 轨迹按承载报文方向过滤(对向数据的确认
 * 由反方向报文携带),避免两个 ISN 空间混在一个轴上。
 * 对向没有数据段也没有缺口时返回 null(单向数据流无需对向视图)。
 */
export function buildOppositeSeqSpaceView(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  event: TcpEvent,
): { dir: StreamDirection; view: SeqSpaceView } | null {
  const opp: StreamDirection = event.direction === 'c2s' ? 's2c' : 'c2s'
  // SYN/FIN 各消耗 1 字节,不算数据 —— 只认纯载荷,避免仅有握手的对向产出 1 字节伪视图
  const oppSegs = facts.segments.filter((s) => s.direction === opp && s.payloadLen > 0)
  const oppGaps = facts.gaps.filter((g) => g.direction === opp)
  if (oppSegs.length === 0 && oppGaps.length === 0) return null

  // 轴范围:对向数据的最小 seq 到最大 seq+len(缺口边界并入)。回绕流不做对向视图
  // (展开绝对坐标在无事件锚点时无意义)。
  let a0 = Infinity
  let a1 = -Infinity
  for (const s of oppSegs) {
    a0 = Math.min(a0, s.seq)
    a1 = Math.max(a1, (s.seq + s.seqLen) >>> 0)
  }
  for (const g of oppGaps) {
    a0 = Math.min(a0, g.start)
    a1 = Math.max(a1, g.end)
  }
  if (!Number.isFinite(a0) || !Number.isFinite(a1) || a1 <= a0) return null

  const clip = ([s, e]: [number, number]): [number, number] | null =>
    e <= a0 || s >= a1 ? null : [Math.max(s, a0), Math.min(e, a1)]

  const seenRuns = mergeRanges(oppSegs.map((s) => [s.seq, (s.seq + s.seqLen) >>> 0] as [number, number]))
    .map(clip)
    .filter((r): r is [number, number] => r != null)
  const gaps = oppGaps.map((g) => [g.start, g.end] as [number, number]).filter((r) => clip(r) != null)

  // 方向锚点:facts 中任一有方向归属的段的源端点(与 buildCompareViewModel 同法)
  let c2sKey: string | null = null
  for (const s of facts.segments) {
    const p = packets.find((q) => q.number === s.packetNumber)
    if (!p) continue
    if (s.direction === 'c2s') {
      c2sKey = `${p.srcIp ?? '?'}:${p.srcPort ?? 0}`
      break
    }
  }
  const dirOf = (p: Packet): 'c2s' | 's2c' => {
    if (!c2sKey) return p.srcPort != null && p.dstPort != null && p.srcPort < p.dstPort ? 'c2s' : 's2c'
    return `${p.srcIp ?? '?'}:${p.srcPort ?? 0}` === c2sKey ? 'c2s' : 's2c'
  }

  // 对向数据的确认/SACK 由方向 !== opp 的报文携带
  const sackRaw: Array<[number, number]> = []
  const ackTrack: Array<{ time: number; ack: number }> = []
  for (const p of packets) {
    if (dirOf(p) === opp) continue
    for (const b of p.tcpSackBlocks ?? []) sackRaw.push(b)
    if (p.tcpAck != null) ackTrack.push({ time: p.time, ack: p.tcpAck })
  }
  ackTrack.sort((x, y) => x.time - y.time)

  return {
    dir: opp,
    view: {
      axisMin: a0,
      axisMax: a1,
      ticks: ticksFor(a0, a1),
      seenRuns,
      gaps,
      sackBlocks: mergeRanges(sackRaw)
        .map(clip)
        .filter((r): r is [number, number] => r != null)
        .slice(0, SEQ_VIEW_MAX_SACK),
      ackTrack,
      retxArrow: undefined, // 对向无事件聚焦,无重传箭头
      rangeLabels: buildRangeLabels(facts, packets, seenRuns, gaps, a0, a1),
    },
  }
}

/**
 * 播放时刻 -> 当前阶段索引。
 * 边界语义:首阶段开始前为 -1;落在某阶段 [t0,t1] 内返回该索引;
 * 最后阶段结束后停在最后一个索引(终态驻留,与案例分镜 S8 一致)。
 */
export function stageAtTime(vm: CompareViewModel, t: number): number {
  const { stages } = vm
  if (stages.length === 0) return -1
  for (let i = stages.length - 1; i >= 0; i--) {
    if (t >= stages[i].t0) return i
  }
  return -1
}
