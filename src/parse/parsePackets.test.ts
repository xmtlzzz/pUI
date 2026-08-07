import { describe, expect, it } from 'vitest'
import { parsePackets } from './parsePackets'

const raw = JSON.stringify([
  {
    _source: {
      layers: {
        frame: {
          'frame.number': '1',
          'frame.time_relative': '0.000000',
          'frame.len': '74',
          'frame.protocols': 'eth:ethertype:ip:tcp:http',
        },
        eth: { 'eth.src': '00:11:22:33:44:55', 'eth.dst': '00:aa:bb:cc:dd:ee' },
        ip: { 'ip.src': '192.168.1.10', 'ip.dst': '93.184.216.34' },
        tcp: { 'tcp.srcport': '54321', 'tcp.dstport': '80', 'tcp.flags': '0x0002' },
        http: { 'http.request.method': 'GET', 'http.request.uri': '/', 'http.host': 'example.com' },
      },
    },
  },
])

describe('parsePackets', () => {
  it('maps tshark json layers to Packet fields', () => {
    const packets = parsePackets(raw)
    expect(packets).toHaveLength(1)
    const p = packets[0]
    expect(p.number).toBe(1)
    expect(p.time).toBeCloseTo(0.0)
    expect(p.len).toBe(74)
    expect(p.transport).toBe('tcp')
    expect(p.proto).toBe('http')
    expect(p.srcIp).toBe('192.168.1.10')
    expect(p.dstIp).toBe('93.184.216.34')
    expect(p.srcPort).toBe(54321)
    expect(p.dstPort).toBe(80)
    expect(p.tcpFlags).toBe('0x0002')
    expect(p.httpMethod).toBe('GET')
    expect(p.httpUri).toBe('/')
    expect(p.info).toContain('GET')
    expect(p.direction).toBe('other') // 方向在聚合阶段确定
  })

  it('derives transport from the protocol stack', () => {
    const udpRaw = JSON.stringify([
      { _source: { layers: { frame: { 'frame.number': '1', 'frame.time_relative': '0', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:udp' }, udp: { 'udp.srcport': '54322', 'udp.dstport': '53' } } } },
    ])
    const [p] = parsePackets(udpRaw)
    expect(p.transport).toBe('udp')
    expect(p.srcPort).toBe(54322)
    expect(p.dstPort).toBe(53)
  })

  it('falls back to app protocol when no transport layer present', () => {
    const arpRaw = JSON.stringify([
      { _source: { layers: { frame: { 'frame.number': '1', 'frame.time_relative': '0', 'frame.len': '42', 'frame.protocols': 'eth:ethertype:arp' } } } },
    ])
    const [p] = parsePackets(arpRaw)
    expect(p.transport).toBe('arp')
    expect(p.proto).toBe('arp')
  })
})
