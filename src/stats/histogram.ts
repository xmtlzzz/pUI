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

/** 时间窗重叠过滤:会话区间与 [start,end] 有交集即保留 */
export function overlapRange(convs: Conversation[], range: { start: number; end: number }): Conversation[] {
  return convs.filter((c) => c.start <= range.end && c.end >= range.start)
}
