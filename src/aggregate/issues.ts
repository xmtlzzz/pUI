import type { Conversation, ConversationIssue } from '../model/types'

/**
 * 会话级可疑丢包/异常检测。
 *
 * 场景:「本地发出请求 → 对端可能收到并回包,但本地未收到响应」在抓包里的体现
 * 通常是请求在,响应缺失。这里用可达的数据做规则推断(非 TCP 序列号级精确判断):
 * - TCP:SYN 发出但无 SYN-ACK → 连接未建立
 * - HTTP:有请求但全程无响应 → 响应可能丢失
 * - DNS:有查询但无响应
 * - 会话仅含请求方向(无任何响应)→ 单向,可能丢包
 */
export function analyzeConversationIssues(conv: Conversation): ConversationIssue[] {
  const issues: ConversationIssue[] = []
  const packets = conv.packets
  const transport = packets[0]?.transport
  if (!packets.length) return issues

  // 1. TCP SYN 无 SYN-ACK
  if (transport === 'tcp') {
    const syn = packets.find((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x02) !== 0)
    const synAck = packets.find((p) => p.tcpFlags && (parseInt(p.tcpFlags, 16) & 0x12) === 0x12)
    if (syn && !synAck) {
      issues.push({ type: 'syn-no-reply', message: `TCP 连接未建立:SYN(#${syn.number})未收到 SYN-ACK`, packetNumber: syn.number })
    }
  }

  // 2. HTTP 请求无响应
  const httpReq = packets.find((p) => p.httpMethod != null)
  const hasHttpResp = packets.some((p) => p.httpCode != null)
  if (httpReq && !hasHttpResp) {
    issues.push({ type: 'unanswered', message: `HTTP 请求(#${httpReq.number})未收到响应`, packetNumber: httpReq.number })
  }

  // 3. DNS 查询无响应
  const dnsQuery = packets.find((p) => p.dnsQuery != null && p.direction === 'request')
  const hasDnsResp = packets.some((p) => p.proto === 'dns' && p.direction === 'response')
  if (dnsQuery && !hasDnsResp) {
    issues.push({ type: 'unanswered', message: `DNS 查询(#${dnsQuery.number})未收到响应`, packetNumber: dnsQuery.number })
  }

  // 4. 会话仅见请求方向(无任何响应)
  if (!issues.length) {
    const hasAnyResp = packets.some((p) => p.direction === 'response')
    if (!hasAnyResp) {
      issues.push({ type: 'one-way', message: '会话仅见请求方向,未收到任何响应(可能丢包)' })
    }
  }

  return issues
}
