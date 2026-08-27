import type { Packet } from '../model/types'

/**
 * M5 Capture Quality(plan M5):采集完整性统计。
 *
 * frame.cap_len < frame.len 即该帧被 snaplen 截断 —— 这是**采集侧信号**
 * (snaplen 设置、镜像口限速、ring buffer 丢弃),不是网络丢包证据:
 * 报文可能完好到达了对端,只是抓包工具没抓全。截断占比高时,基于载荷的
 * 一切分析(字段缺失导致的"无法判断")都应回看本统计。
 *
 * frame.cap_len 整字段缺失(旧版 tshark 导出)时 available=false:无数据不断言。
 */

export interface CaptureQuality {
  /** capLen 字段可用(至少一个报文带该字段) */
  available: boolean
  /** 截断帧数(cap_len < len) */
  truncatedCount: number
  /** 截断比例(分母 = 带 capLen 字段的报文数;available=false 时 undefined) */
  truncatedRatio?: number
  /** 截断报文号(升序,截断数 > 100 时截断列表防止极端抓包撑爆 UI) */
  truncatedPackets: number[]
}

const MAX_LISTED = 100

export function computeCaptureQuality(packets: Packet[]): CaptureQuality {
  let withCapLen = 0
  let truncated = 0
  const truncatedPackets: number[] = []
  for (const p of packets) {
    if (p.capLen == null) continue
    withCapLen++
    if (p.capLen < p.len) {
      truncated++
      if (truncatedPackets.length < MAX_LISTED) truncatedPackets.push(p.number)
    }
  }
  if (withCapLen === 0) {
    return { available: false, truncatedCount: 0, truncatedPackets: [] }
  }
  return {
    available: true,
    truncatedCount: truncated,
    truncatedRatio: truncated / withCapLen,
    truncatedPackets,
  }
}
