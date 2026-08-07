import type { Conversation, ConversationIssue } from '../model/types'

/** http.time 超过该阈值(秒)视为慢响应 */
const SLOW_RESPONSE_THRESHOLD = 1.0

/**
 * 会话级可疑丢包/异常检测。
 *
 * 场景:「本地发出请求 → 对端可能收到并回包,但本地未收到响应」在抓包里的体现
 * 通常是请求在,响应缺失;TCP 则表现为重传/乱序/未关闭等。用可达数据做规则推断:
 * - TCP:SYN 发出但无 SYN-ACK → 连接未建立
 * - HTTP:有请求但全程无响应 → 响应可能丢失
 * - DNS:有查询但无响应
 * - 会话仅含请求方向(无任何响应)→ 单向,可能丢包
 * - TCP 未正常关闭(无 FIN)
 * - TCP 重传 / 乱序(tshark tcp.analysis.*)
 * - TCP 被 RST 重置
 * - 响应延迟异常(http.time 过大)
 */
export function analyzeConversationIssues(conv: Conversation): ConversationIssue[] {
  const issues: ConversationIssue[] = []
  const packets = conv.packets
  const transport = packets[0]?.transport
  if (!packets.length) return issues

  // 1. TCP 相关
  if (transport === 'tcp') {
    const syn = packets.find((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x02) !== 0)
    const synAck = packets.find((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x12) === 0x12)
    if (syn && !synAck) {
      issues.push({ type: 'syn-no-reply', message: `TCP 连接未建立:SYN(#${syn.number})未收到 SYN-ACK`, packetNumber: syn.number })
    }
    const hasFin = packets.some((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x01) !== 0)
    if (!hasFin) {
      issues.push({ type: 'no-close', message: 'TCP 连接未正常关闭(未收到 FIN)' })
    }
    const retrans = packets.filter((p) => p.tcpAnalysis?.includes('retransmission') || p.tcpAnalysis?.includes('fast-retransmission'))
    if (retrans.length) {
      issues.push({ type: 'retransmission', message: `检测到 ${retrans.length} 次 TCP 重传,可能存在丢包`, packetNumber: retrans[0].number })
    }
    const ooo = packets.filter((p) => p.tcpAnalysis?.includes('out-of-order'))
    if (ooo.length) {
      issues.push({ type: 'retransmission', message: `检测到 ${ooo.length} 个乱序报文`, packetNumber: ooo[0].number })
    }
    const rst = packets.find((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x04) !== 0)
    if (rst) {
      issues.push({ type: 'rst', message: `TCP 连接被重置(RST #${rst.number})`, packetNumber: rst.number })
    }
  }

  // 2. HTTP 请求无响应
  const httpReq = packets.find((p) => p.httpMethod != null)
  const hasHttpResp = packets.some((p) => p.httpCode != null)
  if (httpReq && !hasHttpResp) {
    issues.push({ type: 'unanswered', message: `HTTP 请求(#${httpReq.number})未收到响应`, packetNumber: httpReq.number })
  }

  // 3. 慢响应(http.time 为请求→响应延迟)
  const slow = packets.filter((p) => p.httpTime != null && p.httpTime > SLOW_RESPONSE_THRESHOLD)
  if (slow.length) {
    const worst = Math.max(...slow.map((s) => s.httpTime as number))
    issues.push({ type: 'slow-response', message: `存在慢响应(最长 ${worst.toFixed(2)}s),可能有丢包/延迟` })
  }

  // 4. DNS 查询无响应
  const dnsQuery = packets.find((p) => p.dnsQuery != null && p.direction === 'request')
  const hasDnsResp = packets.some((p) => p.proto === 'dns' && p.direction === 'response')
  if (dnsQuery && !hasDnsResp) {
    issues.push({ type: 'unanswered', message: `DNS 查询(#${dnsQuery.number})未收到响应`, packetNumber: dnsQuery.number })
  }

  // 5. 会话仅见请求方向(无任何响应)
  if (!issues.length) {
    const hasAnyResp = packets.some((p) => p.direction === 'response')
    if (!hasAnyResp) {
      issues.push({ type: 'one-way', message: '会话仅见请求方向,未收到任何响应(可能丢包)' })
    }
  }

  return issues
}
