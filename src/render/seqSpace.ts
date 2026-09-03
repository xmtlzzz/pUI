import type { Packet } from '../model/types'
import { analyzeStream, type StreamAnalysisFacts, type StreamDirection } from '../analysis/tcp/streamAnalysis.ts'
import { seqDiff, seqGt } from '../analysis/tcp/seq'

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
  /** 非 TCP 回退时间轴带的报文线段(TCP 带为空)。t=相对时刻(秒),
   *  dir=a2b/b2a/neutral(线段方向),label 形如 "#3 概要 · 120B" */
  messages: Array<{ packetNumber: number; seq: number; t: number; dir: 'a2b' | 'b2a' | 'neutral'; label: string; proto: string; anomaly: boolean }>
  /** 带性质:tcp=字节序号空间;fallback=时间轴(报文序号) */
  kind: 'tcp' | 'fallback'
  /** 带的协议名(回退带显示;TCP 带恒 'tcp') */
  proto: string
  /** 该带是否检测到 2^32 序列号回绕(轴已降级为最大连续块;UI 可据此提示)。
   *  跨回绕流的 32 位原始 seq 数值跨度可达 4e9,直接画会造出十亿字节级幻影缺口。 */
  wrapAround?: boolean
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
    // 非 TCP(或缺 seq/len):回退**时间轴线条交互图**(用户要求 2026-09-02:
    // ICMP 等报文也要线条形式的时序图,不是点点点)。按 协议+端点对 分组,
    // 组内轴=相对时间秒(与 A/B 形态同坐标),每报文一条水平线段:
    // request/本端发出 → 向右(a2b),response/对端发出 → 向左(b2a),
    // 判不了用中性虚线。方向判定优先 Packet.direction,缺失按源端点。
    const groups = new Map<
      string,
      {
        proto: string
        label: string
        srcKey: string
        msgs: Array<{ packetNumber: number; seq: number; t: number; dir: 'a2b' | 'b2a' | 'neutral'; label: string; proto: string; anomaly: boolean }>
      }
    >()
    for (const p of ordered) {
      const a = `${p.srcIp ?? p.srcMac ?? '?'}:${p.srcPort ?? ''}`
      const b = `${p.dstIp ?? p.dstMac ?? '?'}:${p.dstPort ?? ''}`
      const pair = [a, b].sort().join('↔')
      const key = `${p.proto}|${pair}`
      let g = groups.get(key)
      if (!g) {
        g = { proto: p.proto, label: `${a} ↔ ${b} · ${p.proto}`, srcKey: a, msgs: [] }
        groups.set(key, g)
      }
      // 方向:Packet.direction 优先;缺失时按源端点(与组内首个方向一致按源=组标签左端)
      let dir: 'a2b' | 'b2a' | 'neutral'
      if (p.direction === 'request') dir = 'a2b'
      else if (p.direction === 'response') dir = 'b2a'
      else {
        const src = `${p.srcIp ?? p.srcMac ?? '?'}:${p.srcPort ?? ''}`
        dir = src === g.srcKey ? 'a2b' : 'b2a'
      }
      g.msgs.push({
        packetNumber: p.number,
        seq: p.number, // 保留序号(x 落位由 t 决定)
        t: p.time,
        dir,
        label: `#${p.number} ${p.info ?? p.proto} · ${p.len}B`,
        proto: p.proto,
        anomaly: (p.tcpAnalysis?.length ?? 0) > 0,
      })
    }
    const lanes: SeqSpaceLane[] = []
    for (const g of groups.values()) {
      const ts = g.msgs.map((m) => m.t)
      const axisMin = Math.min(...ts)
      const rawMax = Math.max(...ts)
      // 单包/同时刻带:轴两端留 1ms 呼吸,除零保护
      const axisMax = rawMax === axisMin ? axisMin + 0.001 : rawMax
      lanes.push({
        direction: 'c2s',
        label: g.label,
        axisMin,
        axisMax,
        seenRuns: [],
        gaps: [],
        sackBlocks: [],
        retxMarks: [],
        marks: [],
        ticks: ticksFor(axisMin, axisMax),
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
  // 在两个 ISN 空间之间来回跳 —— m4 ackTrack 同一条原则)。
  // 跨 2^32 回绕:ack 是 32 位环序,用 seqGt(环上前进)取代数值 > ——
  // 数值比较在回绕后会停在回绕前的大值(4294967290 > 100),游标画错位置。
  const finalAck: Record<StreamDirection, number | undefined> = { c2s: undefined, s2c: undefined }
  for (const sg of facts.segments) {
    const p = packetByNumber.get(sg.packetNumber)
    if (!p?.tcpAck) continue
    const target: StreamDirection = sg.direction === 'c2s' ? 's2c' : 'c2s'
    const cur = finalAck[target]
    if (cur == null || seqGt(p.tcpAck, cur)) finalAck[target] = p.tcpAck
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
  // 复杂度护栏:缺口按 end 升序排序后单遍归并对向 ACK(ack 也按序推进游标),
  // O(N + G log G);此前逐缺口内层循环是 O(N×G),高缺口率大会话直接卡死主线程。
  {
    const gapEnds = facts.gaps
      .map((g) => ({ dir: g.direction, end: g.end, done: false }))
      // 按环序排序(seqDiff):raw 数值排序在跨回绕时会把回绕后的 gap end(如 100)
      // 排到回绕前的大值(如 4294967260)之前 —— 与下方 ack 游标单调推进不匹配,
      // 恢复标记会错位。seqDiff 是「环上有符号距离」,正常跨度(<2^31)下即环序。
      .sort((a, b) => seqDiff(a.end, b.end))
    // 对向 ACK 序列:每方向收集(ack, number),按时间序(=ordered)天然按报文序
    const ackSeq: Record<StreamDirection, Array<{ ack: number; number: number }>> = { c2s: [], s2c: [] }
    for (const p of ordered) {
      if (p.tcpAck == null) continue
      const carry = dirOf(p, c2sKey)
      ackSeq[carry === 'c2s' ? 's2c' : 'c2s'].push({ ack: p.tcpAck, number: p.number })
    }
    for (const dir of ['c2s', 's2c'] as const) {
      const list = ackSeq[dir]
      let ai = 0
      for (const ge of gapEnds) {
        if (ge.dir !== dir || ge.done) continue
        // 环序判定:ack 是否「不越过」缺口终点(ge.end)。跨回绕时缺口终点回绕为
        // 小值(如 100),数值比较会把 W+ 区间的 ACK(4294967260)误判为「<= 100」
        // 而提前消费 —— 与 finalAck 游标修复同一原则,恢复标记也必须用环距。
        while (ai < list.length && seqDiff(list[ai].ack, ge.end) <= 0) ai++
        if (ai < list.length) {
          ge.done = true
          marks[dir].push({ packetNumber: list[ai].number, seq: list[ai].ack, len: 0, kind: 'ack' })
        }
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
    // 已见条/缺口渲染护栏:超上限时把相邻区间**合并为聚合带**(保留轴范围与
    // 总量语义,悬停 title 标注聚合了几段),DOM 不随缺口数线性爆炸。
    // 采样会丢区间,合并不丢 —— 事实边界仍在轴上。
    const mergedSeen = mergeRanges(seenRaw)
    const mergedGaps = laneGaps
    // 2^32 回绕守卫:32 位原始 seq 的数值跨度跨过半空间(0x7fffffff)时,环上相邻的
    // 数据在数值轴上相距 ~4e9,直接画会造出十亿字节级幻影缺口(数据被挤到两端、
    // 中间全是红斜纹)。与 m4 viewModel.buildPanoramaView 同款守卫 —— 降级为
    // 最大连续已见块(轴收窄到该块,事实边界保留,wrapAround 置位供 UI 提示)。
    let wrapAround = false
    if (axisMax - axisMin > 0x7fffffff) {
      wrapAround = true
      // 降级为最大连续已见块:从 seenRuns 中选最宽的一段作为轴(初始化用首块,
      // 不能从原始轴跨度起算 —— 那正是要降级的 4e9 跨度,永远不会被替换)
      let bestStart = mergedSeen.length ? mergedSeen[0][0] : axisMin
      let bestEnd = mergedSeen.length ? mergedSeen[0][1] : axisMax
      for (const [s, e] of mergedSeen) {
        if (e - s > bestEnd - bestStart) {
          bestStart = s
          bestEnd = e
        }
      }
      axisMin = bestStart
      axisMax = bestEnd
    }
    if (mergedSeen.length > SEQ_SPACE_MAX_RANGES || mergedGaps.length > SEQ_SPACE_MAX_RANGES) {
      const coalesced = coalesceRanges(mergedSeen, mergedGaps, SEQ_SPACE_MAX_RANGES)
      lanes.push({
        direction: dir,
        label: labelOf(dir),
        axisMin,
        axisMax,
        seenRuns: coalesced.seen,
        gaps: coalesced.gaps,
        sackBlocks: mergeRanges(sackRaw[dir]).slice(0, SEQ_SPACE_MAX_SACK),
        finalAck: finalAck[dir],
        retxMarks: sampleMark(retxMarks[dir], SEQ_SPACE_MAX_MARKS),
        marks: sampleMark(sortedMarks, SEQ_SPACE_MAX_MARKS),
        ticks: ticksFor(axisMin, axisMax),
        messages: [],
        kind: 'tcp',
        proto: 'tcp',
        wrapAround,
      })
      continue
    }
    lanes.push({
      direction: dir,
      label: labelOf(dir),
      axisMin,
      axisMax,
      seenRuns: mergedSeen,
      gaps: mergedGaps,
      sackBlocks: mergeRanges(sackRaw[dir]).slice(0, SEQ_SPACE_MAX_SACK),
      finalAck: finalAck[dir],
      retxMarks: sampleMark(retxMarks[dir], SEQ_SPACE_MAX_MARKS),
      marks: sampleMark(sortedMarks, SEQ_SPACE_MAX_MARKS),
      ticks: ticksFor(axisMin, axisMax),
      messages: [],
      kind: 'tcp',
      proto: 'tcp',
      wrapAround,
    })
  }

  return { lanes, width: 720 } // 与 FaultCompare.SeqSpaceGraphic 同宽,主视图面板放得下
}

/** 已见条/缺口渲染上限:轴显示宽 ~700px,300 条以上人眼已不可分辨,合并为聚合带 */
export const SEQ_SPACE_MAX_RANGES = 300

/**
 * 把已见条与缺口合并为聚合带:把轴等分成 target 份,每份内所有已见段并成
 * 一个聚合段(记合并数),所有缺口并成一个聚合缺口;聚合段保持"已收/未收"
 * 的定性结论(份内只要有缺口就整份含缺口),总量语义不丢。
 * 纯函数、确定性。 */
function coalesceRanges(
  seen: Array<[number, number]>,
  gaps: Array<[number, number]>,
  target: number,
): { seen: Array<[number, number]>; gaps: Array<[number, number]> } {
  if (seen.length === 0 && gaps.length === 0) return { seen: [], gaps: [] }
  let lo = Infinity
  let hi = -Infinity
  for (const [s, e] of seen) {
    lo = Math.min(lo, s)
    hi = Math.max(hi, e)
  }
  for (const [s, e] of gaps) {
    lo = Math.min(lo, s)
    hi = Math.max(hi, e)
  }
  if (!Number.isFinite(lo) || hi <= lo) return { seen, gaps }
  const span = hi - lo
  const binWidth = span / target
  const binOf = (v: number): number => Math.min(target - 1, Math.max(0, Math.floor((v - lo) / binWidth)))
  const seenBins: Array<[number, number] | null> = new Array(target).fill(null)
  const gapBins: Array<[number, number] | null> = new Array(target).fill(null)
  for (const [s, e] of seen) {
    const b = binOf(s)
    const cur = seenBins[b]
    seenBins[b] = cur ? [Math.min(cur[0], s), Math.max(cur[1], e)] : [s, e]
  }
  for (const [s, e] of gaps) {
    const b = binOf(s)
    const cur = gapBins[b]
    gapBins[b] = cur ? [Math.min(cur[0], s), Math.max(cur[1], e)] : [s, e]
  }
  return {
    seen: seenBins.filter((r): r is [number, number] => r != null),
    gaps: gapBins.filter((r): r is [number, number] => r != null),
  }
}
