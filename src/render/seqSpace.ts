import type { Packet } from '../model/types'
import { analyzeStream, type StreamAnalysisFacts, type StreamDirection } from '../analysis/tcp/streamAnalysis.ts'

/**
 * 序列号空间形态时序图(用户要求 2026-09-01:不要「两条生命线 + 水平报文箭头」
 * 的横排报文交互,要 FaultCompare 序列空间条带图那种读法 —— 一条横向字节轴,
 * 绿色已收数据条 / 红斜纹缺口 / 紫 SACK / 蓝色累计 ACK 游标 / 红色重传标记)。
 *
 * TCP 会话:每方向一条带(c2s 在上、s2c 在下,两个 ISN 空间不混轴),每条带
 * 就是一张「第二张图」。
 *
 * 非 TCP 会话(stp/arp/lldp/mdns/dns/…,2026-09-01 用户要求所有协议可渲染):
 * 没有 TCP 序号空间,回退为**时间轴带** —— 轴=报文序号(1..N),每个报文一个
 * 刻度点,按 协议+端点对 分带;同样复用条带视觉语言(点=报文,可点击看详情)。
 *
 * 纯函数 + 确定性(O(n) 单遍为主,SACK 合并排序 O(n log n));
 * 组件只把结果映射为 SVG。
 */

/** SACK 渲染护栏:单带超过此数的块截断(极端抓包的 SACK 风暴不拖垮 DOM) */
export const SEQ_SPACE_MAX_SACK = 100
/** 证据标注渲染护栏:单带 marks/retxMarks 上限,超出均匀采样
 *  (2026-09-01 用户实测:2.3 万包的大会话满屏三角渲染极慢) */
export const SEQ_SPACE_MAX_MARKS = 200

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
  /** 非 TCP 回退时间轴带的报文点位(TCP 带为空);label 形如 "#3 概要 · 120B" */
  messages: Array<{ packetNumber: number; seq: number; label: string; proto: string; anomaly: boolean }>
  /** 带性质:tcp=字节序号空间;fallback=时间轴(报文序号) */
  kind: 'tcp' | 'fallback'
  /** 带的协议名(回退带显示;TCP 带恒 'tcp') */
  proto: string
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

/** 渲染护栏的均匀采样:保留首尾,中间等步取点,输出按原序(O(n)) */
function sampleMark<T>(arr: T[], max: number): T[] {
  if (arr.length <= max) return arr
  const out: T[] = []
  const stride = (arr.length - 1) / (max - 1)
  for (let i = 0; i < max; i++) out.push(arr[Math.round(i * stride)])
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

  if (facts.segments.length === 0) {
    // 非 TCP(或缺 seq/len):回退时间轴带。按 协议+端点对 分组,组内轴=报文序号。
    // 分组键稳定性:协议 + 无向端点对(两端排序),同组报文在时间轴上从左到右。
    const groups = new Map<string, { proto: string; label: string; msgs: Array<{ packetNumber: number; seq: number; label: string; proto: string; anomaly: boolean }> }>()
    for (const p of ordered) {
      const a = `${p.srcIp ?? p.srcMac ?? '?'}:${p.srcPort ?? ''}`
      const b = `${p.dstIp ?? p.dstMac ?? '?'}:${p.dstPort ?? ''}`
      const pair = [a, b].sort().join('↔')
      const key = `${p.proto}|${pair}`
      let g = groups.get(key)
      if (!g) {
        g = { proto: p.proto, label: `${a} ↔ ${b} · ${p.proto}`, msgs: [] }
        groups.set(key, g)
      }
      g.msgs.push({
        packetNumber: p.number,
        seq: p.number, // 时间轴带:x=报文序号(非字节)
        label: `#${p.number} ${p.info ?? p.proto} · ${p.len}B`,
        proto: p.proto,
        anomaly: (p.tcpAnalysis?.length ?? 0) > 0,
      })
    }
    const lanes: SeqSpaceLane[] = []
    for (const g of groups.values()) {
      const nums = g.msgs.map((m) => m.seq)
      const axisMin = Math.min(...nums)
      const axisMax = Math.max(...nums)
      lanes.push({
        direction: 'c2s',
        label: g.label,
        axisMin,
        axisMax: axisMax === axisMin ? axisMin + 1 : axisMax, // 单包带给 1 格跨度,除零保护
        seenRuns: [],
        gaps: [],
        sackBlocks: [],
        retxMarks: [],
        marks: [],
        ticks: ticksFor(axisMin, axisMax === axisMin ? axisMin + 1 : axisMax),
        messages: sampleMark(g.msgs, SEQ_SPACE_MAX_MARKS),
        kind: 'fallback',
        proto: g.proto,
      })
    }
    return { lanes, width: 720 }
  }

  // 每方向:报文 → seq 占位端点(含 SYN/FIN 各占 1;与 analyzeStream 同规则)
  const dirMap = new Map<number, StreamDirection>()
  for (const sg of facts.segments) dirMap.set(sg.packetNumber, sg.direction)

  // 一次性建号查表(此前 packets.find 是 O(n²),2.3 万包实测拖慢渲染)
  const packetByNumber = new Map(packets.map((p) => [p.number, p]))

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
    const p = packetByNumber.get(sg.packetNumber)
    if (!p?.tcpAck) continue
    const target: StreamDirection = sg.direction === 'c2s' ? 's2c' : 'c2s'
    const cur = finalAck[target]
    if (cur == null || p.tcpAck > cur) finalAck[target] = p.tcpAck
  }

  // 重传/证据标记:tcpAnalysis 含 retransmission → retx;越过缺口暴露缺口 →
  // expose;填补缺口的乱序段 → fill。全部有渲染上限(均匀采样),大会话不爆 DOM。
  const retxMarks: Record<StreamDirection, SeqSpaceLane['retxMarks']> = { c2s: [], s2c: [] }
  const marks: Record<StreamDirection, SeqSpaceLane['marks']> = { c2s: [], s2c: [] }
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
  // 恢复 ACK:每个缺口只取**首个**确认值越过其终点的对向报文(缺口被确认 =
  // 已恢复,一次就够)。此前是"每个越过的 ACK 都标",大会话几千个 ACK 满屏三角。
  const gapEnds = facts.gaps.map((g) => ({ dir: g.direction, end: g.end, done: false }))
  for (const p of ordered) {
    if (p.tcpAck == null) continue
    const carry = dirOf(p, c2sKey)
    for (const ge of gapEnds) {
      if (ge.done || carry === ge.dir) continue // 确认由对向报文携带
      if (p.tcpAck > ge.end) {
        ge.done = true
        marks[ge.dir].push({ packetNumber: p.number, seq: p.tcpAck, len: 0, kind: 'ack' })
      }
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
    const sortedMarks = marks[dir].sort((a, b) => a.seq - b.seq)
    lanes.push({
      direction: dir,
      label: labelOf(dir),
      axisMin,
      axisMax,
      seenRuns: mergeRanges(seenRaw),
      gaps: laneGaps,
      sackBlocks: mergeRanges(sackRaw[dir]).slice(0, SEQ_SPACE_MAX_SACK),
      finalAck: finalAck[dir],
      retxMarks: sampleMark(retxMarks[dir], SEQ_SPACE_MAX_MARKS),
      marks: sampleMark(sortedMarks, SEQ_SPACE_MAX_MARKS),
      ticks: ticksFor(axisMin, axisMax),
      messages: [],
      kind: 'tcp',
      proto: 'tcp',
    })
  }

  return { lanes, width: 720 } // 与 FaultCompare.SeqSpaceGraphic 同宽,主视图面板放得下
}
