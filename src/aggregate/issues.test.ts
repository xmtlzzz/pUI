import { describe, expect, it } from 'vitest'
import { aggregateConversations } from './aggregateConversations'
import { analyzeConversationIssues } from './issues'
import type { Conversation, Packet } from '../model/types'

function pkt(
  n: number,
  t: number,
  proto: string,
  transport: 'tcp' | 'udp',
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
  extra: Partial<Packet> = {},
): Packet {
  return { number: n, time: t, len: 60, transport, proto, srcIp, dstIp, srcPort, dstPort, direction: 'other', ...extra }
}

describe('丢包/异常会话检测', () => {
  it('flags HTTP request with no response', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', httpUri: '/' }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'unanswered' && i.message.includes('HTTP'))).toBe(true)
  })

  it('flags SYN with no SYN-ACK', () => {
    const packets = [pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' })]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'syn-no-reply')).toBe(true)
  })

  it('flags DNS query with no response', () => {
    const packets = [pkt(1, 0, 'dns', 'udp', '192.168.1.10', 54322, '8.8.8.8', 53, { dnsQuery: 'example.com' })]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'unanswered' && i.message.includes('DNS'))).toBe(true)
  })

  it('does NOT flag a normal HTTP request/response session with proper close', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 0.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200' }),
      pkt(5, 0.3, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0011' }),
      pkt(6, 0.31, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0011' }),
      pkt(7, 0.32, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0010' }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues).toHaveLength(0)
  })

  it('flags TCP connection without FIN close', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0010' }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'no-close')).toBe(true)
  })

  it('flags retransmission via tcpAnalysis', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 0.4, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', tcpAnalysis: ['retransmission'] }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'retransmission')).toBe(true)
  })

  it('flags slow response via httpTime', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 3.0, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200', httpTime: 2.95 }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'slow-response')).toBe(true)
  })

  it('flags RST reset', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0014' }), // RST+ACK
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'rst')).toBe(true)
  })

  it('SYN 被 RST 拒绝时只报 rst,不误报 syn-no-reply / no-close', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }), // SYN
      pkt(2, 0.01, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0014' }), // RST+ACK
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).toContain('rst')
    expect(types).not.toContain('syn-no-reply')
    expect(types).not.toContain('no-close')
  })

  it('flags lost-segment with its own issue type', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200', tcpAnalysis: ['lost-segment'] }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'lost-segment')).toBe(true)
  })

  it('flags duplicate-ack with its own issue type', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', tcpAnalysis: ['duplicate-ack'] }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues.some((i) => i.type === 'dup-ack')).toBe(true)
  })

  it('慢响应阈值可配置:低于默认 1.0 时按参数判定', () => {
    const conv: Conversation = {
      id: 'k', client: 'a:80', server: 'b:80', protocol: 'http', packetCount: 2, bytes: 120,
      start: 0, end: 0.8, duration: 0.8, issues: [],
      packets: [
        pkt(1, 0, 'http', 'tcp', 'a', 12345, 'b', 80, { httpMethod: 'GET', direction: 'request' }),
        pkt(2, 0.8, 'http', 'tcp', 'b', 80, 'a', 12345, { httpCode: '200', httpTime: 0.8, direction: 'response' }),
      ],
    }
    expect(analyzeConversationIssues(conv).some((i) => i.type === 'slow-response')).toBe(false) // 0.8 < 默认 1.0
    expect(analyzeConversationIssues(conv, { slowResponseThreshold: 0.5 }).some((i) => i.type === 'slow-response')).toBe(true)
  })

  it('aggregateConversations 透传阈值选项', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', 'a', 12345, 'b', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', 'b', 80, 'a', 12345, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', 'a', 12345, 'b', 80, { httpMethod: 'GET', direction: 'request' }),
      pkt(4, 0.9, 'http', 'tcp', 'b', 80, 'a', 12345, { httpCode: '200', httpTime: 0.85, direction: 'response' }),
    ]
    const convs = aggregateConversations(packets, { slowResponseThreshold: 0.5 })
    expect(convs[0].issues.some((i) => i.type === 'slow-response')).toBe(true)
  })

  // ---------- 真实流量形态回归(对照实际 TCP/HTTP/DNS 行为) ----------

  it('TLS 握手会话(无 HTTP 应用层)不误报 unanswered/one-way', () => {
    // 真实 TLS:握手包 proto=tls,没有 http.request.line/code,不该被当成 HTTP 请求无响应
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 443, { tcpFlags: '0x0002' }), // SYN
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 443, '192.168.1.10', 54321, { tcpFlags: '0x0012' }), // SYN-ACK
      pkt(3, 0.04, 'tls', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 443, { tlsType: '1' }), // ClientHello
      pkt(4, 0.05, 'tls', 'tcp', '93.184.216.34', 443, '192.168.1.10', 54321, { tlsType: '2' }), // ServerHello
      pkt(5, 0.06, 'tls', 'tcp', '93.184.216.34', 443, '192.168.1.10', 54321, { tlsType: '11' }), // Certificate
      pkt(6, 0.07, 'tls', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 443, { tlsType: '20' }), // Finished
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).not.toContain('unanswered')
    expect(types).not.toContain('one-way')
  })

  it('UDP 查询发出但响应丢失 → one-way(真实:丢包/防火墙静默丢弃)', () => {
    // 真实场景:QUIC/NTP 之类无 SYN 的 UDP,响应被丢弃时只有请求方向
    const packets = [pkt(1, 0, 'dns', 'udp', '192.168.1.10', 54322, '8.8.8.8', 53, { dnsQuery: 'lost.example.com' })]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).toContain('unanswered') // DNS 层给出更精确结论
    expect(types).not.toContain('one-way') // unanswered 已覆盖,one-way 被抑制(更精确优先,避免双报)
  })

  it('HTTP 204/304 等无 body 响应(code 存在)不误报 unanswered', () => {
    // 真实:204 No Content / 304 Not Modified 响应无 body,但 http.response.code 在 → 算已响应
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 0.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '204' }),
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).not.toContain('unanswered')
  })

  it('SYN 重传后成功建立连接的会话:方向正确、只报重传、不误报连接未建立', () => {
    // 真实网络:首次 SYN 丢失会重传;两个 SYN + SYN-ACK 表示连接已建立
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }), // SYN
      pkt(2, 1.0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002', tcpAnalysis: ['retransmission'] }), // SYN 重传
      pkt(3, 1.01, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }), // SYN-ACK
      pkt(4, 1.02, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(5, 1.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200' }),
    ]
    const convs = aggregateConversations(packets)
    const c = convs[0]
    expect(c.client).toBe('192.168.1.10:54321') // 重传 SYN 不影响方向判定
    const types = c.issues.map((i) => i.type)
    expect(types).not.toContain('syn-no-reply') // 有 SYN-ACK → 连接建立
    expect(types).toContain('retransmission') // 重传确实发生(真实证据)
  })

  it('Keep-Alive 会话:部分请求无响应但有响应可达时不误报 unanswered(保守语义)', () => {
    // 真实 keep-alive:一次连接多个请求,可能仅最后一个悬挂——无法可靠区分,"任一响应即不报"是保守正确
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', httpUri: '/a' }),
      pkt(4, 0.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200' }),
      pkt(5, 0.3, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', httpUri: '/b' }), // 悬挂 /b
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).not.toContain('unanswered') // 有任一响应 → 保守不报
    expect(types).toContain('no-close') // 未关闭仍报
  })

  it('中途抓包片段(首包即数据段,无 SYN/FIN)不误报 no-close / lost-segment', () => {
    // tshark 在流起始给首个数据段打 lost-segment 是公认假阳性;无 SYN 说明抓包从连接中途开始
    const packets = [
      pkt(1, 0, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET', tcpAnalysis: ['lost-segment'] }),
      pkt(2, 0.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200' }),
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).not.toContain('no-close')
    expect(types).not.toContain('lost-segment')
  })

  it('HTTP 请求被 RST 拒绝时只报 rst,不误报 unanswered', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 0.06, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0014' }), // RST+ACK
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).toContain('rst')
    expect(types).not.toContain('unanswered')
  })

  it('仅请求方向+重传时同时报 one-way 与 retransmission(不互相掩盖)', () => {
    // 无 SYN 的数据段+重传:真正的结论是「没收到任何响应」,不能被重传标签盖住
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0018' }),
      pkt(2, 0.8, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0018', tcpAnalysis: ['retransmission'] }),
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).toContain('one-way')
    expect(types).toContain('retransmission')
  })

  it('flags out-of-order with type out-of-order, not retransmission', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200', tcpAnalysis: ['out-of-order'] }),
    ]
    const convs = aggregateConversations(packets)
    const types = convs[0].issues.map((i) => i.type)
    expect(types).toContain('out-of-order')
    expect(types).not.toContain('retransmission')
  })
})
