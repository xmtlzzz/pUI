import { describe, expect, it } from 'vitest'
import { buildPacketTree } from './packetTree'
import type { Packet } from '../model/types'

function pkt(extra: Partial<Packet>): Packet {
  return { number: 1, time: 0.5, len: 120, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', srcPort: 12345, dstIp: '2.2.2.2', dstPort: 80, direction: 'request', ...extra }
}

describe('buildPacketTree', () => {
  it('TCP+HTTP 包按帧/L2/L3/L4/应用层分层', () => {
    const tree = buildPacketTree(pkt({ tcpFlags: '0x0018', httpMethod: 'GET', httpUri: '/', srcMac: 'aa:01', dstMac: 'bb:02' }))
    expect(tree.map((n) => n.key)).toEqual(['frame', 'l2', 'l3', 'tcp', 'app'])
    expect(tree[0].children?.map((c) => c.key)).toContain('time')
    const tcp = tree.find((n) => n.key === 'tcp')!
    expect(tcp.children?.find((c) => c.key === 'flags')?.value).toContain('TCP PSH-ACK')
    const app = tree.find((n) => n.key === 'app')!
    expect(app.label).toBe('应用层 HTTP')
  })

  it('UDP/DNS 无 TCP 字段', () => {
    const tree = buildPacketTree(pkt({ transport: 'udp', proto: 'dns', dstPort: 53, dnsQuery: 'example.com', tcpFlags: undefined }))
    expect(tree.map((n) => n.key)).toEqual(['frame', 'l3', 'udp', 'app'])
    const udp = tree.find((n) => n.key === 'udp')!
    expect(udp.children?.find((c) => c.key === 'analysis')).toBeUndefined()
  })

  it('ARP 帧无网络/传输层', () => {
    const tree = buildPacketTree(pkt({ transport: 'arp', proto: 'arp', srcIp: undefined, dstIp: undefined, srcMac: 'aa:01', dstMac: 'bb:02' }))
    expect(tree.map((n) => n.key)).toEqual(['frame', 'l2', 'arp'])
  })

  it('缺字段不生成空节点', () => {
    const tree = buildPacketTree(pkt({}) as Packet)
    expect(tree.map((n) => n.key)).not.toContain('l2')
    expect(tree.find((n) => n.key === 'frame')!.children!.length).toBeGreaterThanOrEqual(6)
  })
})