import type { Packet, Direction } from '../model/types'
import { hostOf } from '../model/types'

export interface LayoutMessage {
  id: number
  fromLeft: boolean
  x1: number
  y1: number
  x2: number
  y2: number
  time: number
  len: number
  info: string
  proto: string
  direction: Direction
}

export interface SequenceLayout {
  width: number
  height: number
  messages: LayoutMessage[]
}

export const CLIENT_X = 80
export const SERVER_X = 340
/** 顶部端点标签区高度(给客户端/服务端标签留白,避免与第一条报文重叠) */
export const HEADER_H = 40
export const TOP = HEADER_H + 12
const ROW_H = 30
const SLOPE = 22

export function layoutSequence(packets: Packet[], style: 'A' | 'B', client: string, _server: string): SequenceLayout {
  const n = Math.max(packets.length, 1)
  const height = TOP + n * ROW_H + 20
  const clientIp = hostOf(client)

  const messages: LayoutMessage[] = packets.map((p, i) => {
    const y = TOP + i * ROW_H
    const fromLeft = p.direction === 'request' ? true : p.direction === 'response' ? false : p.srcIp === clientIp
    const base = {
      id: p.number,
      fromLeft,
      time: p.time,
      len: p.len,
      info: p.info ?? '',
      proto: p.proto,
      direction: p.direction,
    }
    if (style === 'A') {
      const y2 = y + SLOPE
      return fromLeft
        ? { ...base, x1: CLIENT_X, y1: y, x2: SERVER_X, y2 }
        : { ...base, x1: SERVER_X, y1: y, x2: CLIENT_X, y2 }
    }
    return fromLeft
      ? { ...base, x1: CLIENT_X, y1: y, x2: SERVER_X, y2: y }
      : { ...base, x1: SERVER_X, y1: y, x2: CLIENT_X, y2: y }
  })

  return { width: 520, height, messages }
}
