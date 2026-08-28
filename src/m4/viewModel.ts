import type { Packet } from '../model/types'
import type { StreamAnalysisFacts, StreamDirection } from '../analysis/tcp/streamAnalysis'
import type { TcpEvent } from '../analysis/tcp/events'
import type { EventStage } from '../analysis/tcp/stages'
import { seqDiff } from '../analysis/tcp/seq'

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
  /**
   * 全景视图(M5 完整 SSV):事件方向**全部**字节范围的序列空间(轴=数据最小 seq 到
   * 最大 seq+len,缺口并入)。与 seqSpace 同一构建机制,仅轴范围不同;
   * 回绕流(展开跨度异常)不提供全景,为 null。
   */
  panorama: SeqSpaceView | null
  /**
   * 事件方向的全部缺口(未按图形视窗裁剪)。seqSpace.gaps 只画视窗内的缺口,
   * 证据导出必须列全,否则会少报缺失(有测试钉住)。
   */
  allGaps: Array<[number, number]>
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
    kindLabel: kindLabelFor(e),
    severity: severityZh(e.severity),
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

/** 严重度/置信度的中文展示(low/medium/high 原始枚举不直接面向用户) */
export function severityZh(v: string): string {
  return v === 'low' ? '低' : v === 'medium' ? '中' : v === 'high' ? '高' : v
}

/**
 * 事件的展示标签。乱序分类在低置信模糊区(引擎自述"无法排除该段确曾丢失")
 * 不得以断言语气进入 headline/切换器,降级为「疑似」。
 */
export function kindLabelFor(event: TcpEvent): string {
  if (event.kind === 'reordering' && event.inference.confidence === 'low') return '疑似乱序(迟到补齐)'
  return KIND_LABEL[event.kind]
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

/**
 * 报文的展示方向:以 facts.segments 的方向归属为准(分析层以流内首包源端点定义
 * c2s,每个报文——含纯 ACK——都在 segments 里有方向记录)。自建锚点(如"首个
 * 载荷段")在纯 ACK 开头的中途抓包里会与分析层分属两端,导致关键报文链与导出
 * 报告的方向箭头整体反转 —— 方向语义只允许一个来源。
 */
function directionOf(p: Packet, dirMap: Map<number, StreamDirection>): 'c2s' | 's2c' {
  const d = dirMap.get(p.number)
  if (d) return d
  return p.srcPort != null && p.dstPort != null && p.srcPort < p.dstPort ? 'c2s' : 's2c'
}

/**
 * 从事件的证据结构推断报文的事件角色(渲染在报文旁的醒目标注)。
 * 依据是 detectTcpEvents 输出的确定性字段(packet 相等性),不是对文本的猜测。
 * 伪重传的「确认无变化」需调用方先核实恢复 ACK 与重传前等值(spuriousAckUnchanged),
 * 未核实/不等值时降级为「确认」—— 不做无证据的断言。
 */
function roleBadgeOf(packetNumber: number, event: TcpEvent, spuriousAckUnchanged: boolean): string | undefined {
  if (event.originalSegmentPacket === packetNumber && event.gap) return '缺口显露'
  if (event.retransmissionPacket === packetNumber) {
    return event.kind === 'reordering' ? '迟到补齐' : event.gap ? '重传回补' : '冗余重传'
  }
  if (event.recoveryAckPacket === packetNumber) {
    if (event.kind !== 'possible-ack-loss-or-spurious') return '恢复'
    return spuriousAckUnchanged ? '确认无变化' : '确认'
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

  // 报文方向表:与分析层同源(segments 覆盖全部报文,含纯 ACK),见 directionOf 注释
  const dirMap = new Map<number, StreamDirection>()
  for (const sg of facts.segments) dirMap.set(sg.packetNumber, sg.direction)

  // 伪重传徽标「确认无变化」必须先核实:恢复 ACK 与重传前(同方向)ACK 等值。
  // 引擎的 recoveryAck 只是"重发后第一条反向 ACK",期间可能有新数据被确认
  const ackDir: StreamDirection = event.direction === 'c2s' ? 's2c' : 'c2s'
  let spuriousAckUnchanged = false
  if (event.kind === 'possible-ack-loss-or-spurious' && event.retransmissionPacket != null && event.recoveryAckPacket != null) {
    const retxT = packets.find((p) => p.number === event.retransmissionPacket)?.time
    const after = packets.find((p) => p.number === event.recoveryAckPacket)
    const before = retxT != null
      ? packets
          .filter((p) => p.time < retxT && p.tcpAck != null && dirMap.get(p.number) === ackDir)
          .sort((a, b) => a.time - b.time)
          .pop()
      : undefined
    spuriousAckUnchanged = after?.tcpAck != null && before?.tcpAck != null && seqDiff(after.tcpAck, before.tcpAck) === 0
  }

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
        dir: directionOf(p, dirMap),
        label: labelParts.join(' ') || 'TCP',
        flags: p.tcpFlags,
        seq: p.tcpSeq,
        ack: p.tcpAck,
        len: p.tcpLen,
        sackBlocks: p.tcpSackBlocks,
        tags: p.tcpAnalysis,
        stageIndex: stageIdx,
        roleBadge: roleBadgeOf(p.number, event, spuriousAckUnchanged),
      }
    })

  // ---- 序列空间图形化(案例文档核心承诺):已见字节条 + Gap hatch + SACK 块 + ACK 轨迹 ----
  const retxPkt = event.retransmissionPacket != null ? packets.find((p) => p.number === event.retransmissionPacket) : undefined
  const seqSpace = buildSeqSpaceView(facts, packets, event, retxPkt?.tcpSeq)
  // 全景视图(M5 完整 SSV):事件方向全部字节范围;回绕流为 null(UI 隐藏入口)
  const panorama = buildPanoramaView(facts, packets, event, retxPkt?.tcpSeq)
  // 对向视图(双向流):事件方向之外那一侧的静态字节空间
  const opposite = buildOppositeSeqSpaceView(facts, packets, event)

  const card: EventCard = {
    kindLabel: kindLabelFor(event),
    severity: severityZh(event.severity),
    recovered: event.recovered,
    gapText: gapTextOf(event),
    observations: event.observations.map((o) => ({ packetNumber: o.packetNumber, statement: o.statement })),
    inference: { statement: event.inference.statement, confidence: severityZh(event.inference.confidence) },
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

  // headline:无缺口(伪重传类)时不再拼出「缺口 无」;严重度/置信度以中文呈现
  const gapPart = gapTextOf(event) != null ? `缺口 ${gapTextOf(event)}` : '无缺口'
  return {
    card,
    seqSpace,
    keyPackets,
    stages: bandStages,
    referenceSteps: buildReferenceSteps(),
    marks,
    direction: event.direction,
    opposite,
    panorama,
    allGaps: facts.gaps
      .filter((g) => g.direction === event.direction)
      .map((g) => [g.start, g.end] as [number, number]),
    degraded: {
      unorderableInput: facts.unorderableInput,
      midStream: facts.midStream,
      lengthUnavailable: facts.lengthUnavailable,
      noEvents: false,
    },
    headline: `${kindLabelFor(event)} · ${gapPart} · ${severityZh(event.severity)}`,
  }
}

/**
 * 缩放步进(M5 完整 SSV):以当前窗口(缺省=基准全轴)中心按 factor 缩放,
 * 钳制在基准轴内并保住最小跨度。factor>1 放大,<1 缩小。纯函数。
 */
export function zoomStep(
  base: { axisMin: number; axisMax: number },
  cur: { start: number; end: number } | null,
  factor: number,
): { start: number; end: number } {
  const bMin = base.axisMin
  const bMax = base.axisMax
  const full = bMax - bMin
  const c = cur ?? { start: bMin, end: bMax }
  const minSpan = Math.max(8, full / 1000)
  const span = Math.min(Math.max((c.end - c.start) / factor, minSpan), full)
  const center = (c.start + c.end) / 2
  const s0 = Math.min(Math.max(center - span / 2, bMin), bMax - span)
  return { start: s0, end: s0 + span }
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
  return buildSeqSpaceAxisView(facts, packets, event, Math.max(0, a0 - pad), a1 + pad, retxSeq)
}

/**
 * 全景视图(M5 完整 SSV):事件方向全部字节范围。轴=数据最小 seq 到最大 seq+len
 * (缺口并入);回绕流的原始 seq 展开跨度在全景轴上无意义,返回 null。
 */
export function buildPanoramaView(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  event: TcpEvent,
  retxSeq: number | undefined,
): SeqSpaceView | null {
  let a0 = Infinity
  let a1 = -Infinity
  for (const seg of facts.segments) {
    if (seg.direction !== event.direction || seg.seqLen <= 0) continue
    a0 = Math.min(a0, seg.seq)
    a1 = Math.max(a1, (seg.seq + seg.seqLen) >>> 0)
  }
  for (const g of facts.gaps) {
    if (g.direction !== event.direction) continue
    a0 = Math.min(a0, g.start)
    a1 = Math.max(a1, g.end)
  }
  if (!Number.isFinite(a0) || !Number.isFinite(a1) || a1 <= a0) return null
  // 回绕守卫:32 位序号空间下,混入"未展开的外来 ISN"会让跨度爆炸,
  // 此时全景轴没有意义(缺口邻域视图不受影响)
  if (a1 - a0 > 0x7fffffff) return null
  return buildSeqSpaceAxisView(facts, packets, event, a0, a1, retxSeq)
}

/** 序列空间轴构建核心:给定轴范围,方向过滤+裁剪地填充全部图元(gap 邻域与全景共用) */
function buildSeqSpaceAxisView(
  facts: StreamAnalysisFacts,
  packets: Packet[],
  event: TcpEvent,
  axisMin: number,
  axisMax: number,
  retxSeq: number | undefined,
): SeqSpaceView {
  // 轴以事件方向的 ISN 空间为中心,因此**只画该方向**的数据:已见条/缺口按
  // direction 过滤,SACK/ACK 游标只认 ackDir(对向数据的确认由对向报文携带)。
  // 不过滤会把两个 ISN 空间混进同一坐标轴(对向视图已落实同一条原则)。
  const dirMap = new Map<number, StreamDirection>()
  for (const sg of facts.segments) dirMap.set(sg.packetNumber, sg.direction)
  const ackDir: StreamDirection = event.direction === 'c2s' ? 's2c' : 'c2s'

  const clip = ([s, e]: [number, number]): [number, number] | null =>
    e <= axisMin || s >= axisMax ? null : [Math.max(s, axisMin), Math.min(e, axisMax)]

  // 已见字节:从 facts 的段分类重建(有载荷的段按 seq+len 并入;用简单合并,数量有限)
  const seenRaw: Array<[number, number]> = []
  for (const seg of facts.segments) {
    if (seg.seqLen <= 0 || seg.direction !== event.direction) continue
    seenRaw.push([seg.seq, (seg.seq + seg.seqLen) >>> 0])
  }
  const seenRuns = mergeRanges(seenRaw)
    .map(clip)
    .filter((r): r is [number, number] => r != null)

  const gaps = facts.gaps
    .filter((g) => g.direction === event.direction)
    .map((g) => clip([g.start, g.end]))
    .filter((r): r is [number, number] => r != null)

  const sackRaw: Array<[number, number]> = []
  for (const p of packets) {
    if (dirMap.get(p.number) !== ackDir) continue
    for (const b of p.tcpSackBlocks ?? []) sackRaw.push(b)
  }
  const sackBlocks = mergeRanges(sackRaw)
    .map(clip)
    .filter((r): r is [number, number] => r != null)
    .slice(0, SEQ_VIEW_MAX_SACK)

  // ACK 轨迹:对向报文的 (time, ack) 序列 —— 混入事件方向自身的 ACK 会让
  // 游标在两个 ISN 空间之间来回跳(看起来像 ACK 倒退)
  const ackTrack = packets
    .filter((p) => p.tcpAck != null && dirMap.get(p.number) === ackDir)
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
    rangeLabels: buildRangeLabels(facts, packets, seenRuns, gaps, axisMin, axisMax, event.direction),
  }
}

/**
 * 缩放裁剪(M5 完整 SSV):把任意序列空间视图裁剪到 [start,end] 子轴。
 * 纯函数、确定性;图元越界部分截断、完全越界丢弃,ACK 轨迹按值过滤,
 * 刻度按新轴重算。start/end 会被钳制回原轴范围。
 */
export function clipSeqSpaceView(sq: SeqSpaceView, start: number, end: number): SeqSpaceView {
  const s0 = Math.max(sq.axisMin, Math.min(start, end))
  const e0 = Math.min(sq.axisMax, Math.max(start, end))
  if (e0 <= s0) return sq
  const clip = ([s, e]: [number, number]): [number, number] | null =>
    e <= s0 || s >= e0 ? null : [Math.max(s, s0), Math.min(e, e0)]
  const clamp1 = (v: number): number => Math.min(e0, Math.max(s0, v))
  return {
    axisMin: s0,
    axisMax: e0,
    ticks: ticksFor(s0, e0),
    seenRuns: sq.seenRuns.map(clip).filter((r): r is [number, number] => r != null),
    gaps: sq.gaps.map(clip).filter((r): r is [number, number] => r != null),
    sackBlocks: sq.sackBlocks.map(clip).filter((r): r is [number, number] => r != null),
    ackTrack: sq.ackTrack.filter((a) => a.ack >= s0 && a.ack <= e0),
    retxArrow: sq.retxArrow,
    rangeLabels: (sq.rangeLabels ?? [])
      .map((l) => ({ ...l, start: clamp1(l.start), end: clamp1(l.end) }))
      .filter((l) => l.end > l.start)
      .sort((a, b) => a.start - b.start),
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
  dir: StreamDirection,
): SeqSpaceView['rangeLabels'] {
  const axisSpan = axisMax - axisMin
  const labels: SeqSpaceView['rangeLabels'] = []
  for (const [s, e] of seenRuns) {
    labels.push({ start: s, end: e, text: seenRunLabel(facts, packets, s, e, dir), kind: 'seen' })
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
  dir: StreamDirection,
): string {
  const mid = s + Math.floor((e - s) / 2)
  for (const seg of facts.segments) {
    if (seg.seqLen <= 0 || seg.direction !== dir) continue
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

  // 方向归属:与分析层同源的报文方向表(见 directionOf 注释)
  const dirMap = new Map<number, StreamDirection>()
  for (const sg of facts.segments) dirMap.set(sg.packetNumber, sg.direction)

  // 对向数据的确认/SACK 由方向 !== opp 的报文携带
  const sackRaw: Array<[number, number]> = []
  const ackTrack: Array<{ time: number; ack: number }> = []
  for (const p of packets) {
    if (dirMap.get(p.number) === opp) continue
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
      rangeLabels: buildRangeLabels(facts, packets, seenRuns, gaps, a0, a1, opp),
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
