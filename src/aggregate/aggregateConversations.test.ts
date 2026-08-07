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
})
