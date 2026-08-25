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
 *
 * 措辞原则(指南第 6、21 节):只描述该标签对应的**机制**,不断言成因。
 * 重传可能源于真实丢包,也可能是伪重传(数据已到、ACK 未被发送端看到)或乱序迟到;
 * 乱序本身不等于丢包;lost-segment 只是当前观察点视角下的推断。
 * 定性结论由 src/analysis/ 的序列空间与事件引擎给出(带证据链与限制说明)。
 */
export function tcpStatHint(key: TcpStatEntry['key'], count: number, total: number): string {
  const ratio = total > 0 ? count / total : 0
  if (key === 'lost-segment') {
    return count === 1
      ? '有 1 个 segment 在当前捕获中缺失(仅代表该观察点未看到,不等于网络丢包)'
      : `${count} 个 segment 在当前捕获中缺失(仅代表该观察点未看到,不等于网络丢包)`
  }
  const heavy = ratio >= HEAVY_RATIO
  if (key === 'retransmission') {
    return heavy
      ? `发现大量重传(${(ratio * 100).toFixed(1)}% 报文),同序号段被重复发送;是否对应真实丢包需结合序列空间缺口判断`
      : count === 1
        ? '仅 1 次重传:偶发,同序号段被重复发送;可能是丢包重发,也可能是确认未被及时看到'
        : `${count} 次重传:同序号段被重复发送;可能是丢包重发,也可能是确认未被及时看到`
  }
  if (key === 'fast-retransmission') {
    return heavy
      ? `发现大量快速重传(${(ratio * 100).toFixed(1)}% 报文),接收端重复 ACK 触发立即重发,提示接收端观察到序列缺口`
      : count === 1
        ? '仅 1 次快速重传:重复 ACK 达到阈值后立即重发,提示接收端观察到序列缺口'
        : `${count} 次快速重传:接收端通过重复 ACK 触发立即重发,提示接收端观察到序列缺口`
  }
  if (key === 'duplicate-ack') {
    return heavy
      ? `发现大量重复 ACK(${(ratio * 100).toFixed(1)}% 报文),接收端累计确认长时间未前进,提示存在未补齐的序列缺口`
      : count === 1
        ? '仅 1 个重复 ACK:接收端重复确认同一序号,可能对应缺口或乱序'
        : `${count} 个重复 ACK:接收端累计确认未前进,常与缺口或乱序同时出现`
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
