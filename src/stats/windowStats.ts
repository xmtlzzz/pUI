import type { Packet } from '../model/types'

/**
 * M5 窗口变化统计(plan M5):接收窗口通告的演化。
 *
 * 语义:窗口字节数是对端**通告值** —— 单观察点只见"对端说自己能收多少",
 * 不见其实际缓冲区。统计报文携带的窗口通告(按时间序,两方向合并呈现)。
 *
 * - changes:与前一个不同值才计一次(重复通告不算变化;首个通告不计);
 * - zeroCount:通告值连续为 0 的合并期数(与 m5Events 零窗口语义一致,这里只计数);
 * - 字段全缺失 available=false;混合缺失按有字段的报文统计(字段缺失 ≠ 0)。
 */

export interface WindowStats {
  /** 至少一个报文带 tcp.window_size 字段 */
  available: boolean
  /** 带窗口字段的报文数 */
  samples: number
  /** 通告值相对上一次不同值的变化次数(首个通告不计) */
  changes: number
  /** 零窗口期数(连续 0 合并) */
  zeroCount: number
  /** 观察到的最小/最大通告值;available=false 时 undefined */
  minBytes?: number
  maxBytes?: number
}

export function computeWindowStats(packets: Packet[]): WindowStats {
  const samples: number[] = []
  let zeroCount = 0
  let changes = 0
  let prev: number | null = null
  let inZero = false
  for (const p of packets) {
    const w = p.tcpWindow
    if (w === undefined) continue // 字段缺失 ≠ 0
    samples.push(w)
    if (w === 0 && !inZero) {
      zeroCount++
      inZero = true
    } else if (w > 0) {
      inZero = false
    }
    if (prev != null && w !== prev) changes++
    prev = w
  }
  if (samples.length === 0) {
    return { available: false, samples: 0, changes: 0, zeroCount: 0 }
  }
  return {
    available: true,
    samples: samples.length,
    changes,
    zeroCount,
    minBytes: Math.min(...samples),
    maxBytes: Math.max(...samples),
  }
}
