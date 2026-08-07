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

  it('does NOT flag a normal HTTP request/response session', () => {
    const packets = [
      pkt(1, 0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { tcpFlags: '0x0002' }),
      pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { tcpFlags: '0x0012' }),
      pkt(3, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, { httpMethod: 'GET' }),
      pkt(4, 0.2, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, { httpCode: '200' }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs[0].issues).toHaveLength(0)
  })
})
