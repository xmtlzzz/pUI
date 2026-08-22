import { describe, expect, it } from 'vitest'
import { aggregateConversations } from './aggregateConversations'
import type { Packet } from '../model/types'

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
