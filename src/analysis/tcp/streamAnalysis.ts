import type { Packet } from '../../model/types'
import { SeqRanges } from './ranges'
import { seqDiff } from './seq'

/** 报文在序列空间中的分类。一个数据段必属且仅属其中一类。 */
export type SegmentClassification =
  /** 紧接已见数据之后的新数据 */
  | 'new-in-order'
  /** 越过空洞的新数据(暴露/扩大 Gap) */
  | 'new-ahead-of-gap'
  /** 全部字节都已见过(原样重发) */
  | 'pure-duplicate'
  /** 部分字节已见过(重叠重传) */
  | 'overlapping-retransmit'
  /** 填平了已存在的空洞 */
  | 'out-of-order-fill'
  /** 不占序列空间(纯 ACK / keep-alive) */
  | 'no-payload'

/** 方向:c2s = 发起方→对端,s2c = 反向。以流内首个观察到的报文源端点为 c2s。 */
export type StreamDirection = 'c2s' | 's2c'

export interface SegmentFact {
  packetNumber: number
  time: number
  direction: StreamDirection
  seq: number
  /** 载荷字节数(不含 SYN/FIN 占用的序列号) */
  payloadLen: number
  /** 该段在序列空间占用的长度(载荷 + SYN/FIN 各 1) */
  seqLen: number
  classification: SegmentClassification
  /** 该段中此前未见过的字节数 */
  newBytes: number
}

/** 序列空间空洞的生命周期 */
export interface SequenceGapFact {
  direction: StreamDirection
  /** 空洞起始序列号(含) */
  start: number
  /** 空洞结束序列号(不含) */
  end: number
  byteCount: number
  /** 首次暴露该空洞的报文(即越过空洞到达的那个段) */
  firstObservedPacket: number
  firstObservedTime: number
  /** 是否有 SACK 报告空洞之后的数据已到达接收端 */
  sackCovered: boolean
  filled: boolean
  filledByPacket?: number
  filledTime?: number
  /** 存续时长(秒);未填补时为 undefined —— 不可用抓包结束时间冒充"已恢复" */
  durationSeconds?: number
}

export interface StreamAnalysisFacts {
  /** tcp.stream(缺失时为 undefined,调用方需据此降级) */
  streamId?: number
  /** 是否为中途抓包(未见完整握手)。为真时"流起始缺数据"不构成丢包证据 */
  midStream: boolean
  /** 是否因缺 tcp.len 而无法推进序列空间 */
  lengthUnavailable: boolean
  segments: SegmentFact[]
  gaps: SequenceGapFact[]
  /** 各方向在序列空间中确实观察到的字节数(去重后:重传/重叠只算一次) */
  seenBytes: Record<StreamDirection, number>
}

const F_FIN = 0x01
const F_SYN = 0x02

function flags(p: Packet): number {
  if (!p.tcpFlags) return 0
  const n = Number.parseInt(p.tcpFlags, 16)
  return Number.isNaN(n) ? 0 : n
}

/** 序列空间占用长度:载荷长度 + SYN/FIN 各消耗一个序列号 */
function seqLenOf(p: Packet, payloadLen: number): number {
  const f = flags(p)
  let n = payloadLen
  if (f & F_SYN) n += 1
  if (f & F_FIN) n += 1
  return n
}

/** 中途抓包判定:优先用 tcp.completeness 位掩码(SYN=1 SYN-ACK=2),
 *  无该字段时回退到"流内是否见过纯 SYN"。 */
function detectMidStream(packets: Packet[]): boolean {
  const withCompleteness = packets.find((p) => p.tcpCompleteness != null)
  if (withCompleteness) {
    // 取流内最大值:completeness 随连接推进单调累积,最大值代表整条流见到的阶段
    let max = 0
    for (const p of packets) if (p.tcpCompleteness != null && p.tcpCompleteness > max) max = p.tcpCompleteness
    return (max & 0x03) === 0
  }
  const hasPureSyn = packets.some((p) => {
    const f = flags(p)
    return (f & F_SYN) !== 0 && (f & 0x10) === 0
  })
  return !hasPureSyn
}

function endpointKey(p: Packet): string {
  return `${p.srcIp ?? p.srcMac ?? '?'}:${p.srcPort ?? 0}`
}

/**
 * 单条 TCP 流的序列空间还原(plan M2)。
 *
 * 逐方向重建"哪些字节确实被观察到",并据此给出空洞的完整生命周期。
 * 关键原则:**只在观察到的数据之间报告空洞**,绝不假设流从某个起点开始 ——
 * 否则中途抓包会因"没见过 0..首序列号"而产出一个几十万字节的幻影 Gap。
 *
 * 本函数只产出事实(observations 的原料),不做任何"是否丢包"的推断;
 * 推断与事件归类由 M3 的事件引擎消费这些事实完成。
 */
export function analyzeStream(packets: Packet[]): StreamAnalysisFacts {
  const ordered = [...packets].sort((a, b) => a.time - b.time || a.number - b.number)
  const midStream = detectMidStream(ordered)
  const streamId = ordered.find((p) => p.tcpStream != null)?.tcpStream

  // 以首包源端点定义 c2s 方向(与 Conversation 的 client/server 无关,保证方向自洽)
  const c2sKey = ordered.length ? endpointKey(ordered[0]) : ''
  const dirOf = (p: Packet): StreamDirection => (endpointKey(p) === c2sKey ? 'c2s' : 's2c')

  const seen: Record<StreamDirection, SeqRanges> = { c2s: new SeqRanges(), s2c: new SeqRanges() }
  // 每方向"已通过 SACK 被对端报告收到"的区间(用于判断 Gap 之后的数据是否已到达)
  const sacked: Record<StreamDirection, SeqRanges> = { c2s: new SeqRanges(), s2c: new SeqRanges() }
  const segments: SegmentFact[] = []
  const openGaps: Record<StreamDirection, SequenceGapFact[]> = { c2s: [], s2c: [] }
  const closedGaps: SequenceGapFact[] = []

  let lengthUnavailable = false

  for (const p of ordered) {
    const dir = dirOf(p)
    // SACK 由 ACK 方向携带,描述的是**对向**数据流的到达情况
    if (p.tcpSackBlocks?.length) {
      const target: StreamDirection = dir === 'c2s' ? 's2c' : 'c2s'
      for (const [l, r] of p.tcpSackBlocks) sacked[target].add(l, r)
    }

    if (p.tcpSeq == null) continue
    if (p.tcpLen == null && (flags(p) & (F_SYN | F_FIN)) === 0) {
      // 无 tcp.len 且非 SYN/FIN:无法确定该段是否携带数据。绝不用 frame.len 冒充载荷长度
      // (帧长含各层头部),否则序列号会推进过头、造出根本不存在的 Gap。
      // 该段按"不占序列空间"处理并置降级标记,由调用方转成 limitation。
      lengthUnavailable = true
    }
    const payloadLen = p.tcpLen ?? 0
    const sl = seqLenOf(p, payloadLen)

    if (sl === 0) {
      segments.push({
        packetNumber: p.number,
        time: p.time,
        direction: dir,
        seq: p.tcpSeq,
        payloadLen: 0,
        seqLen: 0,
        classification: 'no-payload',
        newBytes: 0,
      })
      continue
    }

    const ranges = seen[dir]
    const start = p.tcpSeq
    const end = (start + sl) >>> 0
    const prevHighest = ranges.highest()
    const newBytes = ranges.newBytes(start, end)
    const gapsBefore = ranges.gaps().length

    // 分类:先判重复/重叠,再判是否越洞或补洞
    let classification: SegmentClassification
    if (newBytes === 0) {
      classification = 'pure-duplicate'
    } else if (newBytes < sl) {
      classification = 'overlapping-retransmit'
    } else if (prevHighest != null && seqDiff(start, prevHighest) > 0) {
      classification = 'new-ahead-of-gap'
    } else if (gapsBefore > 0 && prevHighest != null && seqDiff(start, prevHighest) < 0) {
      // 落在已见最高点之前的全新数据 → 填补此前的空洞
      classification = 'out-of-order-fill'
    } else {
      classification = 'new-in-order'
    }

    ranges.add(start, end)

    // 新暴露的空洞:比较加入前后的空洞集合
    if (classification === 'new-ahead-of-gap' && prevHighest != null) {
      const gs = ranges.gaps()
      for (const [gs0, ge0] of gs) {
        const already =
          openGaps[dir].some((g) => g.start === gs0 && g.end === ge0) ||
          closedGaps.some((g) => g.direction === dir && g.start === gs0 && g.end === ge0)
        if (already) continue
        openGaps[dir].push({
          direction: dir,
          start: gs0,
          end: ge0,
          byteCount: seqDiff(ge0, gs0),
          firstObservedPacket: p.number,
          firstObservedTime: p.time,
          sackCovered: false,
          filled: false,
        })
      }
    }

    // 空洞填补检查:仍开放的空洞若已被完整覆盖,则由本报文填平
    if (openGaps[dir].length) {
      const stillOpen: SequenceGapFact[] = []
      for (const g of openGaps[dir]) {
        if (ranges.covers(g.start, g.end)) {
          g.filled = true
          g.filledByPacket = p.number
          g.filledTime = p.time
          g.durationSeconds = p.time - g.firstObservedTime
          closedGaps.push(g)
        } else {
          stillOpen.push(g)
        }
      }
      openGaps[dir] = stillOpen
    }

    segments.push({
      packetNumber: p.number,
      time: p.time,
      direction: dir,
      seq: start,
      payloadLen,
      seqLen: sl,
      classification,
      newBytes,
    })
  }

  // 未填补的空洞:标注 SACK 覆盖情况后并入结果
  const all = [...closedGaps, ...openGaps.c2s, ...openGaps.s2c]
  for (const g of all) {
    // 空洞之后的数据是否已由对端 SACK 报告收到 —— 支撑"数据未及时到达"而非"数据丢失"
    g.sackCovered = !sacked[g.direction].isEmpty() && sacked[g.direction].newBytes(g.end, (g.end + 1) >>> 0) === 0
  }
  // 确定性排序:方向 → 起始序列号 → 首次观察报文号
  all.sort(
    (a, b) =>
      a.direction.localeCompare(b.direction) ||
      seqDiff(a.start, b.start) ||
      a.firstObservedPacket - b.firstObservedPacket,
  )

  return {
    streamId,
    midStream,
    lengthUnavailable,
    segments,
    gaps: all,
    seenBytes: { c2s: seen.c2s.totalBytes(), s2c: seen.s2c.totalBytes() },
  }
}
