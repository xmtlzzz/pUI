import type { Packet } from '../model/types'

export interface Segment {
  index: number
  start: number
  end: number
  packets: Packet[]
  packetCount: number
  bytes: number
}

/** 长会话按空闲间隔切分子事务(Keep-Alive 长连接一幕到底难读时的导航单元)。
 *  相邻报文间隔 > idleGap 秒即切段;报文须已按 time 升序。 */
export function segmentConversation(packets: Packet[], idleGap = 1.0): Segment[] {
  if (!packets.length) return []
  const segments: Segment[] = []
  let cur: Packet[] = [packets[0]]
  for (let i = 1; i < packets.length; i++) {
    if (packets[i].time - packets[i - 1].time > idleGap) {
      segments.push(makeSegment(segments.length, cur))
      cur = []
    }
    cur.push(packets[i])
  }
  segments.push(makeSegment(segments.length, cur))
  return segments
}

function makeSegment(index: number, pkts: Packet[]): Segment {
  let bytes = 0
  const first = pkts[0]
  const last = pkts[pkts.length - 1]
  for (const p of pkts) bytes += p.len
  return { index, start: first.time, end: last.time, packets: pkts, packetCount: pkts.length, bytes }
}