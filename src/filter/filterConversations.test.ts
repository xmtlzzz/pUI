import { describe, expect, it } from 'vitest'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { filterConversations, collectFilterOptions } from './filterConversations'
import { emptyFilter } from '../model/types'
import type { Packet } from '../model/types'

function pkt(n: number, proto: string, srcIp: string, srcPort: number, dstIp: string, dstPort: number, transport: 'tcp' | 'udp' = 'tcp'): Packet {
  return { number: n, time: n, len: 60, transport, proto, srcIp, dstIp, srcPort, dstPort, direction: 'other' }
}

const packets: Packet[] = [
  pkt(1, 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80),
  pkt(2, 'http', '192.168.1.10', 54321, '93.184.216.34', 80),
  pkt(3, 'http', '93.184.216.34', 80, '192.168.1.10', 54321), // HTTP 响应
  pkt(4, 'dns', '192.168.1.10', 54322, '8.8.8.8', 53, 'udp'),
  pkt(5, 'dns', '8.8.8.8', 53, '192.168.1.10', 54322, 'udp'), // DNS 响应
]

describe('filterConversations', () => {
  const convs = aggregateConversations(packets)

  it('filters by protocol (any packet in session)', () => {
    const f = emptyFilter()
    f.protocol = ['http']
    const r = filterConversations(convs, f)
    expect(r).toHaveLength(1)
    expect(r[0].protocol).toBe('http')
  })

  it('applies AND across dimensions', () => {
    const f = emptyFilter()
    f.protocol = ['dns']
    f.dstPort = [53]
    expect(filterConversations(convs, f)).toHaveLength(1)
    f.dstPort = [80]
    expect(filterConversations(convs, f)).toHaveLength(0)
  })

  it('matches src address in either direction of a session', () => {
    const f = emptyFilter()
    f.srcIp = ['93.184.216.34'] // 服务端 IP 也在响应方向作为源
    expect(filterConversations(convs, f).length).toBeGreaterThanOrEqual(1)
  })

  it('supports negate', () => {
    const f = emptyFilter()
    f.protocol = ['dns']
    f.negate = true
    const r = filterConversations(convs, f)
    expect(r).toHaveLength(1)
    expect(r[0].protocol).toBe('http')
  })

  it('empty filter keeps all', () => {
    expect(filterConversations(convs, emptyFilter())).toHaveLength(2)
  })

  it('port filter matches either direction port', () => {
    const f = emptyFilter()
    f.srcPort = [53] // DNS 响应方向源端口为 53
    expect(filterConversations(convs, f)).toHaveLength(1)
  })

  it('filters to issue-only conversations', () => {
    const clean = [
      pkt(1, 'dns', '192.168.1.10', 54322, '8.8.8.8', 53, 'udp'),
      pkt(2, 'dns', '8.8.8.8', 53, '192.168.1.10', 54322, 'udp'), // 有响应
    ]
    const lossy = [pkt(3, 'dns', '192.168.1.10', 54323, '8.8.8.8', 53, 'udp')] // 查询无响应(不同端口,独立会话)
    const all = aggregateConversations([...clean, ...lossy])
    expect(all).toHaveLength(2)
    const f = emptyFilter()
    f.issueOnly = true
    const r = filterConversations(all, f)
    expect(r).toHaveLength(1)
    expect(r[0].packetCount).toBe(1)
  })
})

describe('collectFilterOptions', () => {
  it('extracts distinct protocols/ips/ports', () => {
    const o = collectFilterOptions(packets)
    expect(o.protocols).toContain('http')
    expect(o.protocols).toContain('dns')
    expect(o.srcIps).toContain('192.168.1.10')
    expect(o.ports).toContain(80)
    expect(o.ports).toContain(53)
  })

  it('includes mac addresses for non-ip frames', () => {
    const arp: Packet = { number: 1, time: 0, len: 42, transport: 'arp', proto: 'arp', srcMac: 'aa:bb:cc:dd:ee:01', dstMac: 'aa:bb:cc:dd:ee:02', direction: 'other' }
    const o = collectFilterOptions([arp])
    expect(o.srcIps).toContain('aa:bb:cc:dd:ee:01')
    expect(o.dstIps).toContain('aa:bb:cc:dd:ee:02')
  })
})

describe('filterConversations · mac', () => {
  it('filters sessions by mac address for non-ip frames', () => {
    const arp: Packet = { number: 1, time: 0, len: 42, transport: 'arp', proto: 'arp', srcMac: 'aa:bb:cc:dd:ee:01', dstMac: 'aa:bb:cc:dd:ee:02', direction: 'other' }
    const convs = aggregateConversations([arp])
    const f = emptyFilter()
    f.srcIp = ['aa:bb:cc:dd:ee:01']
    expect(filterConversations(convs, f)).toHaveLength(1)
    f.srcIp = ['00:00:00:00:00:99']
    expect(filterConversations(convs, f)).toHaveLength(0)
  })
})
