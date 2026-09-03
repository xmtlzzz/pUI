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

  it('节点携带协议层字节区域:帧整包/L2/网络层/L4/应用层(估算)', () => {
    const tree = buildPacketTree(pkt({ len: 120, tcpLen: 60, srcMac: 'aa:01', dstMac: 'bb:02', httpMethod: 'GET', httpUri: '/' }))
    expect(tree.find((n) => n.key === 'frame')!.range).toEqual({ start: 0, end: 120 })
    expect(tree.find((n) => n.key === 'l2')!.range).toEqual({ start: 0, end: 14 })
    expect(tree.find((n) => n.key === 'l3')!.range).toEqual({ start: 14, end: 34 })
    expect(tree.find((n) => n.key === 'tcp')!.range).toEqual({ start: 34, end: 54 })
    // 应用层区域用 tcp.len(精确载荷字节数)从帧尾反推,而非头部尺寸估算
    expect(tree.find((n) => n.key === 'app')!.range).toEqual({ start: 60, end: 120 })
  })

  it('UDP 应用层区域按头部尺寸估算(L4 头 8 字节)', () => {
    const tree = buildPacketTree(pkt({ transport: 'udp', proto: 'dns', len: 70, dstPort: 53, dnsQuery: 'example.com', srcMac: 'aa:01', dstMac: 'bb:02' }))
    expect(tree.find((n) => n.key === 'udp')!.range).toEqual({ start: 34, end: 42 })
    expect(tree.find((n) => n.key === 'app')!.range).toEqual({ start: 42, end: 70 })
  })

  it('IPv6 网络层头按 40 字节估算', () => {
    const tree = buildPacketTree(pkt({ srcIp: '2001:db8::1', dstIp: '2001:db8::2', transport: 'tcp', len: 100, srcMac: 'aa:01', dstMac: 'bb:02' }))
    expect(tree.find((n) => n.key === 'l3')!.range).toEqual({ start: 14, end: 54 })
    expect(tree.find((n) => n.key === 'tcp')!.range).toEqual({ start: 54, end: 74 })
  })

  it('ARP 帧区域覆盖 L2 之后全部字节', () => {
    const tree = buildPacketTree(pkt({ transport: 'arp', proto: 'arp', len: 42, srcMac: 'aa:01', dstMac: 'bb:02', srcIp: undefined, dstIp: undefined }))
    expect(tree.find((n) => n.key === 'arp')!.range).toEqual({ start: 14, end: 42 })
  })

  it('区域边界用 cap_len(截断帧的实际捕获字节)', () => {
    const tree = buildPacketTree(pkt({ len: 120, capLen: 60 }))
    expect(tree.find((n) => n.key === 'frame')!.range).toEqual({ start: 0, end: 60 })
  })
})