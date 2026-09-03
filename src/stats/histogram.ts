import type { Conversation, Packet } from '../model/types'

export interface TimeBucket {
  index: number
  start: number
  end: number
  count: number
}

/** 全局时间密度直方图:把报文时间轴均分为 bucketCount 桶,统计各桶报文数。
 *  区间下钻:点击桶即锁定 [start,end] 时间窗,只显示与窗口重叠的会话。 */
export function buildHistogram(packets: Packet[], bucketCount = 24): TimeBucket[] {
  if (!packets.length) return []
  let min = Number.POSITIVE_INFINITY
  let max = Number.NEGATIVE_INFINITY
  for (const p of packets) {
    if (p.time < min) min = p.time
    if (p.time > max) max = p.time
  }
  const span = Math.max(max - min, 1e-9)
  const counts = new Array<number>(bucketCount).fill(0)
  for (const p of packets) {
    const i = Math.min(bucketCount - 1, Math.floor(((p.time - min) / span) * bucketCount))
    counts[i]++
  }
  const step = span / bucketCount
  return counts.map((count, i) => ({ index: i, start: min + step * i, end: i === bucketCount - 1 ? max : min + step * (i + 1), count }))
}

/** 按时间聚合的吞吐桶:与 buildHistogram 同一分桶方式,但累计字节数(tcpLen 优先,
 *  缺失按 frame.len;frame.len 含各层头部,tcpLen 是载荷字节 —— 有 tcpLen 时用它)与报文数。
 *  供「时间分布」区渲染报文数 + 吞吐(KB)双条形。空输入返回 []。 */
export interface ThroughputBucket {
  index: number
  start: number
  end: number
  bytes: number
  packets: number
}

export function throughputBuckets(packets: Packet[], bucketCount = 24): ThroughputBucket[] {
  if (!packets.length) return []
  let min = Number.POSITIVE_INFINITY
  let max = Number.NEGATIVE_INFINITY
  for (const p of packets) {
    if (p.time < min) min = p.time
    if (p.time > max) max = p.time
  }
  const span = Math.max(max - min, 1e-9)
  const bytes = new Array<number>(bucketCount).fill(0)
  const counts = new Array<number>(bucketCount).fill(0)
  for (const p of packets) {
    const i = Math.min(bucketCount - 1, Math.floor(((p.time - min) / span) * bucketCount))
    bytes[i] += p.tcpLen ?? p.len
    counts[i]++
  }
  const step = span / bucketCount
  return bytes.map((b, i) => ({
    index: i,
    start: min + step * i,
    end: i === bucketCount - 1 ? max : min + step * (i + 1),
    bytes: b,
    packets: counts[i]!,
  }))
}

/** 时间窗重叠过滤:会话区间与 [start,end] 有交集即保留 */
export function overlapRange(convs: Conversation[], range: { start: number; end: number }): Conversation[] {
  return convs.filter((c) => c.start <= range.end && c.end >= range.start)
}
