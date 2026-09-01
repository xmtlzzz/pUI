import type { Packet } from '../model/types'
import { analyzeStream, type StreamAnalysisFacts, type StreamDirection } from '../analysis/tcp/streamAnalysis.ts'

/**
 * 序列号空间形态时序图(用户要求 2026-09-01:不要「两条生命线 + 水平报文箭头」
 * 的横排报文交互,要 FaultCompare 序列空间条带图那种读法 —— 一条横向字节轴,
 * 绿色已收数据条 / 红斜纹缺口 / 紫 SACK / 蓝色累计 ACK 游标 / 红色重传标记)。
 *
 * 一个 TCP 会话有两个方向的 ISN 空间,混在一个轴上没有意义(m4 viewModel
 * 同一条原则),因此布局产出**每方向一条带**:c2s 在上、s2c 在下,每条带
 * 就是一张「第二张图」。纯函数 + 确定性(O(n log n),SACK 合并排序主导);
 * 组件只把结果映射为 SVG。
 *
 * 事实来源与 FaultCompare 完全同源:analyzeStream 重建 segments/gaps,
 * Packet.tcpSackBlocks/tcpAck 提供 SACK 与累计确认。不做丢包推断 ——
 * 缺口是「观察层事实」,是否丢包由 FaultCompare 的事件引擎下结论。
 */

/** SACK 渲染护栏:单带超过此数的块截断(极端抓包的 SACK 风暴不拖垮 DOM) */
export const SEQ_SPACE_MAX_SACK = 100

/** 单方向带(一张序列空间图) */
export interface SeqSpaceLane {
  direction: StreamDirection
  /** 带标题:「客户端 → 服务端」(组件画在带左上) */
  label: string
  /** 字节轴范围:该方向数据的最小 seq 到最大 seq+len(SYN/FIN 占位计入) */
  axisMin: number
  axisMax: number
  /** 已见字节连续段(合并后;绿色条) */
  seenRuns: Array<[number, number]>
  /** 缺口区间(红斜纹) */
  gaps: Array<[number, number]>
  /** SACK 块(对端已收、本点未必见过的字节;紫色,上限 100 块) */
  sackBlocks: Array<[number, number]>
  /** 累计确认游标位置(对向报文携带的最大 tcpAck;无确认时 undefined) */
  finalAck?: number
  /** 重传标记(tcpAnalysis 含 retransmission 的报文按 seq 落位;红色) */
  retxMarks: Array<{ packetNumber: number; seq: number; len: number }>
  /** 证据链关键报文标注(暴露缺口/补缺口/恢复 ACK 等;带内三角+帧号) */
  marks: Array<{ packetNumber: number; seq: number; len: number; kind: 'retx' | 'expose' | 'fill' | 'ack' }>
  /** 字节刻度(1/2/5 整步长) */
  ticks: number[]
}

export interface SeqSpaceLayout {
  lanes: SeqSpaceLane[]
  /** 画布宽(SVG viewBox 宽;与旧形态同档) */
  width: number
}

export interface SeqSpaceLayoutOptions {
  /** 会话客户端端点(方向归属与带标签用) */
  client: string
  server?: string
  /** 测试注入口:跳过 analyzeStream(布局函数对 facts 的消费逻辑单独可测) */
  factsOverride?: StreamAnalysisFacts
}

/** 1/2/5 整步长刻度(与 m4 viewModel.ticksFor 同规则,单一定义搬到这里会导致
 *  m4 反向依赖 render,故此处复制实现 —— 两处注释放宽不一致属实现细节) */
function ticksFor(axisMin: number, axisMax: number): number[] {
  if (axisMax <= axisMin) return []
  const rawStep = (axisMax - axisMin) / 5
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)))
  const norm = rawStep / mag
  const step = (norm >= 5 ? 5 : norm >= 2 ? 2 : 1) * mag
  const ticks: number[] = []
  // 浮点累积误差会把步长乘出 12.000000000000002 之类;按步长量化到整数/一位小数
  for (let t = Math.ceil(axisMin / step) * step; t <= axisMax; t += step) {
    ticks.push(Math.round(t * 10) / 10)
  }
  return ticks
}

/** 区间合并:重叠/相邻合并,排序输出(与 m4 mergeRanges 同规则) */
function mergeRanges(ranges: Array<[number, number]>): Array<[number, number]> {
  if (ranges.length === 0) return []
  const sorted = [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const out: Array<[number, number]> = [sorted[0]]
  for (let localI = 1; localI < sorted.length; localI++) {
    const last = out[out.length - 1]
    if (sorted[localI][0] <= last[1]) last[1] = Math.max(last[1], sorted[localI][1])
    else out.push(sorted[localI])
  }
  return out
}

/** 方向判定:与 analyzeStream 同规则 —— 以流内首包源端点为 c2s。
 *  options.client 只用于带标签(显示层),不参与判定(两者不一致时
 *  保证事实层的方向自洽,显示跟随事实) */
function dirOf(p: Packet, c2sKey: string): StreamDirection {
  const key = `${p.srcIp ?? p.srcMac ?? '?'}:${p.srcPort ?? 0}`
  return key === c2sKey ? 'c2s' : 's2c'
}

/**
 * 计算序列号空间布局。确定性:无随机、无时间依赖、只依赖入参。
 */
export function computeSeqSpaceLayout(packets: Packet[], opts: SeqSpaceLayoutOptions): SeqSpaceLayout {
  const facts = opts.factsOverride ?? analyzeStream(packets)

  // 带标签用的端点串:analyzeStream 以首包源端点为 c2s,标签跟随同一判定
  const ordered = [...packets].sort((a, b) => a.time - b.time || a.number - b.number)
  const c2sKey = ordered.length ? `${ordered[0].srcIp ?? ordered[0].srcMac ?? '?'}:${ordered[0].srcPort ?? 0}` : ''
  const labelOf = (dir: StreamDirection): string => {
    const c = ordered.find((p) => dirOf(p, c2sKey) === 'c2s')
    const s = ordered.find((p) => dirOf(p, c2sKey) === 's2c')
    const cEnd = c ? `${c.srcIp ?? c.srcMac ?? '?'}:${c.srcPort ?? 0}` : opts.client
    const sEnd = s ? `${s.srcIp ?? s.srcMac ?? '?'}:${s.srcPort ?? 0}` : (opts.server ?? '?')
    return dir === 'c2s' ? `${cEnd} → ${sEnd}` : `${sEnd} → ${cEnd}`
  }

  // 每方向:报文 → seq 占位端点(含 SYN/FIN 各占 1;与 analyzeStream 同规则)
  const dirMap = new Map<number, StreamDirection>()
  for (const sg of facts.segments) dirMap.set(sg.packetNumber, sg.direction)

  // SACK 归属:SACK 描述**对向**数据的到达情况,由 ACK 方向报文携带 →
  // 归入被描述的那条带(c2s 带的 SACK 来自 s2c 方向报文)
  const sackRaw: Record<StreamDirection, Array<[number, number]>> = { c2s: [], s2c: [] }
  for (const p of packets) {
    if (p.tcpSeq == null) continue
    if (!p.tcpSackBlocks?.length) continue
    const carry = dirOf(p, c2sKey)
    const target: StreamDirection = carry === 'c2s' ? 's2c' : 'c2s'
    for (const b of p.tcpSackBlocks) sackRaw[target].push(b)
  }

  // ACK 游标:对向报文携带的最大累计确认(混入本方向自身的 ACK 会让游标
  // 在两个 ISN 空间之间来回跳 —— m4 ackTrack 同一条原则)
  const finalAck: Record<StreamDirection, number | undefined> = { c2s: undefined, s2c: undefined }
  for (const sg of facts.segments) {
    const p = packets.find((q) => q.number === sg.packetNumber)
    if (!p?.tcpAck) continue
    const target: StreamDirection = sg.direction === 'c2s' ? 's2c' : 'c2s'
    const cur = finalAck[target]
    if (cur == null || p.tcpAck > cur) finalAck[target] = p.tcpAck
  }

  // 重传/证据标记:tcpAnalysis 含 retransmission → retx;越过缺口暴露缺口 →
  // expose;填补缺口的乱序段 → fill;恢复确认(推进过缺口的 ACK)→ ack(由
  // gap.firstObservedPacket 之后的累计确认近似:凡 ack 越过任一缺口终点的对向报文)
  const retxMarks: Record<StreamDirection, SeqSpaceLane['retxMarks']> = { c2s: [], s2c: [] }
  const marks: Record<StreamDirection, SeqSpaceLane['marks']> = { c2s: [], s2c: [] }
  const packetByNumber = new Map(packets.map((p) => [p.number, p]))
  for (const sg of facts.segments) {
    const p = packetByNumber.get(sg.packetNumber)
    if (!p) continue
    const dir = sg.direction
    const isRetx = p.tcpAnalysis?.some((t) => t.includes('retransmission')) ?? false
    if (isRetx) {
      retxMarks[dir].push({ packetNumber: p.number, seq: sg.seq, len: sg.seqLen })
      marks[dir].push({ packetNumber: p.number, seq: sg.seq, len: sg.seqLen, kind: 'retx' })
    }
    if (sg.classification === 'new-ahead-of-gap') {
      marks[dir].push({ packetNumber: p.number, seq: sg.seq, len: sg.seqLen, kind: 'expose' })
    }
    if (sg.classification === 'out-of-order-fill') {
      marks[dir].push({ packetNumber: p.number, seq: sg.seq, len: sg.seqLen, kind: 'fill' })
    }
  }
  // 恢复 ACK:对向确认值越过该方向任一缺口的终点(缺口被确认 = 已恢复)
  const ackMarks: Record<StreamDirection, Set<number>> = { c2s: new Set(), s2c: new Set() }
  for (const g of facts.gaps) {
    for (const p of packets) {
      if (p.tcpAck == null || p.tcpSeq == null) continue
      if (dirOf(p, c2sKey) === g.direction) continue // 确认由对向报文携带
      if (p.tcpAck > g.end) ackMarks[g.direction].add(p.number)
    }
  }
  for (const dir of ['c2s', 's2c'] as const) {
    for (const n of ackMarks[dir]) {
      const p = packetByNumber.get(n)
      const sg = facts.segments.find((q) => q.packetNumber === n)
      // 纯 ACK 报文不在 segments 的 seq 占位里也无所谓:mark 用其 ack 值落位
      marks[dir].push({ packetNumber: n, seq: p?.tcpAck ?? 0, len: 0, kind: 'ack' })
      void sg
    }
  }

  // 装配每方向带
  const lanes: SeqSpaceLane[] = []
  for (const dir of ['c2s', 's2c'] as const) {
    const segs = facts.segments.filter((sg) => sg.direction === dir && sg.seqLen > 0)
    if (segs.length === 0) continue
    let axisMin = Infinity
    let axisMax = -Infinity
    const seenRaw: Array<[number, number]> = []
    for (const sg of segs) {
      const end = (sg.seq + sg.seqLen) >>> 0
      axisMin = Math.min(axisMin, sg.seq)
      axisMax = Math.max(axisMax, end)
      seenRaw.push([sg.seq, end])
    }
    const laneGaps = facts.gaps
      .filter((g) => g.direction === dir)
      .map((g) => [g.start, g.end] as [number, number])
    // 缺口也是序列空间的一部分:并入轴范围(即使没有已见段之外的数据也完整)
    for (const [s, e] of laneGaps) {
      axisMin = Math.min(axisMin, s)
      axisMax = Math.max(axisMax, e)
    }
    lanes.push({
      direction: dir,
      label: labelOf(dir),
      axisMin,
      axisMax,
      seenRuns: mergeRanges(seenRaw),
      gaps: laneGaps,
      sackBlocks: mergeRanges(sackRaw[dir]).slice(0, SEQ_SPACE_MAX_SACK),
      finalAck: finalAck[dir],
      retxMarks: retxMarks[dir],
      marks: marks[dir].sort((a, b) => a.seq - b.seq),
      ticks: ticksFor(axisMin, axisMax),
    })
  }

  return { lanes, width: 720 } // 与 FaultCompare.SeqSpaceGraphic 同宽,主视图面板放得下
}
