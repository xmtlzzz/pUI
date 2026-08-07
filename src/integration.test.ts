import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parsePackets } from './parse/parsePackets'
import { aggregateConversations } from './aggregate/aggregateConversations'
import { filterConversations } from './filter/filterConversations'
import { layoutSequence } from './render/layout'
import { emptyFilter } from './model/types'

function fixture(name: string): string {
  return readFileSync(resolve(process.cwd(), `public/fixtures/examples/parsed/${name}.json`), 'utf-8')
}

describe('http.pcapng end-to-end data pipeline', () => {
  it('parse → aggregate → filter → layout', () => {
    const packets = parsePackets(fixture('http'))
    expect(packets.length).toBeGreaterThanOrEqual(9)

    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
    const conv = convs[0]
    expect(conv.protocol).toBe('http')
    expect(conv.client).toBe('192.168.1.10:54321')
    expect(conv.server).toBe('93.184.216.34:80')
    expect(conv.packetCount).toBe(packets.length)

    const f = emptyFilter()
    f.protocol = ['http']
    expect(filterConversations(convs, f)).toHaveLength(1)

    const layout = layoutSequence(conv.packets, 'A', conv.client, conv.server)
    expect(layout.messages).toHaveLength(conv.packetCount)
    // 首个报文为 SYN(请求,从左到右)
    expect(layout.messages[0].fromLeft).toBe(true)
    // 存在响应方向
    expect(layout.messages.some((m) => !m.fromLeft)).toBe(true)
  })

  it('decodes http request/response summaries', () => {
    const packets = parsePackets(fixture('http'))
    const get = packets.find((p) => p.httpMethod === 'GET')
    expect(get?.httpUri).toBe('/')
    expect(get?.info).toContain('GET')
    const ok = packets.find((p) => p.httpCode === '200')
    expect(ok?.info).toContain('200')
  })
})

describe('dns.pcapng end-to-end', () => {
  it('aggregates a single udp dns conversation with client/server', () => {
    const packets = parsePackets(fixture('dns'))
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
    const c = convs[0]
    expect(c.protocol).toBe('dns')
    expect(c.client).toBe('192.168.1.10:54322')
    expect(c.server).toBe('8.8.8.8:53')
    // 方向:查询=request,响应=response
    expect(c.packets[0].direction).toBe('request')
    expect(c.packets[1].direction).toBe('response')
  })
})

describe('mixed.pcapng end-to-end', () => {
  it('splits arp/dns/http into separate conversations', () => {
    const packets = parsePackets(fixture('mixed'))
    const convs = aggregateConversations(packets)
    const protos = convs.map((c) => c.protocol).sort()
    expect(protos).toContain('arp')
    expect(protos).toContain('dns')
    expect(protos).toContain('http')
  })
})

describe('lossy.pcapng (丢包示例)', () => {
  it('detects retransmission and unanswered request from real tshark output', () => {
    const packets = parsePackets(fixture('lossy'))
    const convs = aggregateConversations(packets)
    const c = convs[0]
    expect(c.protocol).toBe('http')
    const types = c.issues.map((i) => i.type)
    expect(types).toContain('retransmission')
    expect(types).toContain('unanswered')
  })
})
