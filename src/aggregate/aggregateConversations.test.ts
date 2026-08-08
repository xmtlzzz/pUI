import { describe, expect, it } from 'vitest'
import { aggregateConversations } from './aggregateConversations'
import type { Packet } from '../model/types'

function pkt(n: number, t: number, proto: string, transport: 'tcp' | 'udp', srcIp: string, srcPort: number, dstIp: string, dstPort: number, flags?: string): Packet {
  return { number: n, time: t, len: 60, transport, proto, srcIp, dstIp, srcPort, dstPort, tcpFlags: flags, info: proto, direction: 'other' }
}

const httpPackets: Packet[] = [
  pkt(1, 0.0, 'tcp', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, '0x0002'), // SYN
  pkt(2, 0.03, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, '0x0012'), // SYN-ACK
  pkt(3, 0.03, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, '0x0010'), // ACK
  pkt(4, 0.05, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, '0x0018'), // GET
]

describe('aggregateConversations', () => {
  it('merges bidirectional packets into one conversation', () => {
    const convs = aggregateConversations(httpPackets)
    expect(convs).toHaveLength(1)
    const c = convs[0]
    expect(c.packetCount).toBe(4)
    expect(c.bytes).toBe(240)
    expect(c.client).toBe('192.168.1.10:54321')
    expect(c.server).toBe('93.184.216.34:80')
    expect(c.protocol).toBe('http')
    expect(c.packets.map((p) => p.direction)).toEqual(['request', 'response', 'request', 'request'])
  })

  it('groups by transport separately', () => {
    const udp = pkt(1, 0, 'dns', 'udp', '192.168.1.10', 54322, '8.8.8.8', 53)
    const convs = aggregateConversations([...httpPackets, udp])
    expect(convs).toHaveLength(2)
  })

  it('keeps arp conversations with no client role', () => {
    const arp: Packet = { number: 1, time: 0, len: 42, transport: 'arp', proto: 'arp', srcMac: 'aa:bb:cc:dd:ee:01', dstMac: 'aa:bb:cc:dd:ee:02', direction: 'other' }
    const convs = aggregateConversations([arp])
    expect(convs).toHaveLength(1)
    expect(convs[0].protocol).toBe('arp')
  })

  it('sorts packets by time and computes duration', () => {
    const shuffled = [httpPackets[3], httpPackets[1], httpPackets[0], httpPackets[2]]
    const convs = aggregateConversations(shuffled)
    const c = convs[0]
    expect(c.packets.map((p) => p.number)).toEqual([1, 2, 3, 4])
    expect(c.duration).toBeCloseTo(0.05)
  })

  it('assigns correct directions for ipv6 conversations', () => {
    const c6: Packet = { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2001:db8::1', srcPort: 54321, dstIp: '2001:db8::2', dstPort: 443, tcpFlags: '0x0002', direction: 'other' }
    const s6: Packet = { number: 2, time: 0.01, len: 60, transport: 'tcp', proto: 'http', srcIp: '2001:db8::2', srcPort: 443, dstIp: '2001:db8::1', dstPort: 54321, tcpFlags: '0x0012', direction: 'other' }
    const convs = aggregateConversations([c6, s6])
    expect(convs).toHaveLength(1)
    const c = convs[0]
    expect(c.client).toBe('2001:db8::1:54321')
    expect(c.server).toBe('2001:db8::2:443')
    expect(c.packets[0].direction).toBe('request')
    expect(c.packets[1].direction).toBe('response')
  })

  it('does not treat SYN-ACK as the connection initiator (半握手抓包)', () => {
    // 抓包从 SYN 之后开始:首个带 SYN 位的报文是服务端的 SYN-ACK,不能因此反转 client/server
    const synAck = pkt(1, 0.0, 'tcp', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, '0x0012')
    const get = pkt(2, 0.01, 'http', 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80, '0x0018')
    const resp = pkt(3, 0.02, 'http', 'tcp', '93.184.216.34', 80, '192.168.1.10', 54321, '0x0018')
    const convs = aggregateConversations([synAck, get, resp])
    expect(convs).toHaveLength(1)
    const c = convs[0]
    expect(c.client).toBe('192.168.1.10:54321')
    expect(c.server).toBe('93.184.216.34:80')
    expect(c.packets.map((p) => p.direction)).toEqual(['response', 'request', 'response'])
  })

  it('UDP 无 SYN 时,客户端用低端口也不反转方向', () => {
    const req = pkt(1, 0.0, 'dns', 'udp', '192.168.1.10', 1024, '5.6.7.8', 8080)
    const resp = pkt(2, 0.01, 'dns', 'udp', '5.6.7.8', 8080, '192.168.1.10', 1024)
    const convs = aggregateConversations([req, resp])
    const c = convs[0]
    expect(c.client).toBe('192.168.1.10:1024')
    expect(c.server).toBe('5.6.7.8:8080')
    expect(c.packets[0].direction).toBe('request')
    expect(c.packets[1].direction).toBe('response')
  })
})
