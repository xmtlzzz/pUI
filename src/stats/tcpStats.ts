import type { Packet } from '../model/types'

/** 五类 tshark TCP 分析标签的固定展示顺序(重传 → 快速重传 → 重复 ACK → 丢段 → 乱序) */
export type TcpAnalysisKey = 'retransmission' | 'fast-retransmission' | 'duplicate-ack' | 'lost-segment' | 'out-of-order'

const KEYS: readonly TcpAnalysisKey[] = ['retransmission', 'fast-retransmission', 'duplicate-ack', 'lost-segment', 'out-of-order']

export interface TcpStatEntry {
  key: TcpAnalysisKey
  /** 该类标签命中的报文数(一个报文可带多个标签,各类独立计数) */
  count: number
}

/** 会话内报文级 TCP 异常统计:逐包扫描 tcpAnalysis 标签并按类型计数。
 *  输入为会话全量报文(不受时序图分段/抽稀影响),仅输出数量 > 0 的类型。 */
export function deriveTcpStats(packets: Packet[]): TcpStatEntry[] {
  const counts = new Map<TcpAnalysisKey, number>()
  for (const p of packets) {
    if (!p.tcpAnalysis) continue
    for (const tag of p.tcpAnalysis) {
      if ((KEYS as readonly string[]).includes(tag)) {
        counts.set(tag as TcpAnalysisKey, (counts.get(tag as TcpAnalysisKey) ?? 0) + 1)
      }
    }
  }
  return KEYS.filter((k) => counts.has(k)).map((k) => ({ key: k, count: counts.get(k)! }))
}
