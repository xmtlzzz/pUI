import type { TcpStatEntry } from './tcpStats'

export interface TcpStatRow {
  key: TcpStatEntry['key']
  /** 展示名(对齐 Wireshark Expert Information 用语) */
  label: string
  count: number
  /** 解读文案:随数量与占会话报文总数比例动态生成 */
  hint: string
}

const LABELS: Record<TcpStatEntry['key'], string> = {
  retransmission: '重传 Retransmission',
  'fast-retransmission': '快速重传 Fast Retransmission',
  'duplicate-ack': '重复 ACK Duplicate ACK',
  'lost-segment': '丢段 Lost Segment',
  'out-of-order': '乱序 Out-of-Order',
}

/** 占比阈值:超过会话报文数的该比例时,文案从「发现」升级为「大量」 */
const HEAVY_RATIO = 0.1

/**
 * 生成某类标签的解读文案。数量为 0 不应调用(行不渲染)。
 * 文案随内容变动:1 次说「仅 1 次」弱化;占比 ≥10% 说「大量」;中间档按类型给固定解释。
 * lost-segment 语义特殊(缺失段在捕获中不可见,计数即缺失数),单独措辞。
 */
export function tcpStatHint(key: TcpStatEntry['key'], count: number, total: number): string {
  const ratio = total > 0 ? count / total : 0
  if (key === 'lost-segment') {
    return count === 1
      ? '有 1 个 segment 在当前捕获中缺失'
      : `${count} 个 segment 在当前捕获中缺失`
  }
  const heavy = ratio >= HEAVY_RATIO
  if (key === 'retransmission') {
    return heavy
      ? `发现大量重传(${(ratio * 100).toFixed(1)}% 报文),同序号段被重复发送,典型原因是丢包或超时`
      : count === 1
        ? '仅 1 次重传:偶发,同序号段被重复发送,通常是丢包后超时重发'
        : `${count} 次重传:同序号段被重复发送,通常意味着丢包或超时`
  }
  if (key === 'fast-retransmission') {
    return heavy
      ? `发现大量快速重传(${(ratio * 100).toFixed(1)}% 报文),接收端重复 ACK 触发立即重发,网络丢包较严重`
      : count === 1
        ? '仅 1 次快速重传:重复 ACK 达到阈值后立即重发,说明丢包被接收端探测到'
        : `${count} 次快速重传:接收端通过重复 ACK 触发立即重发,通常对应网络丢包`
  }
  if (key === 'duplicate-ack') {
    return heavy
      ? `发现大量重复 ACK(${(ratio * 100).toFixed(1)}% 报文),接收端反复索要同一序号,丢包/乱序明显`
      : count === 1
        ? '仅 1 个重复 ACK:接收端重复确认同一序号,提示可能丢包或乱序'
        : `${count} 个重复 ACK:接收端在索要丢失/乱序的段,常伴随重传出现`
  }
  return heavy
    ? `发现大量乱序(${(ratio * 100).toFixed(1)}% 报文),报文到达顺序与发送顺序不一致,多路径或队列抖动`
    : count === 1
      ? '仅 1 个乱序报文:到达顺序与发送顺序不一致,偶发通常无碍'
      : `${count} 个乱序报文:到达顺序与发送顺序不一致,常见于多路径路由或网络抖动`
}

/** 统计条目 → 表格行(带展示名与动态解读) */
export function tcpStatRows(entries: TcpStatEntry[], total: number): TcpStatRow[] {
  return entries.map((e) => ({ ...e, label: LABELS[e.key], hint: tcpStatHint(e.key, e.count, total) }))
}
