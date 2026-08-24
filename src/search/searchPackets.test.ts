import { describe, expect, it } from 'vitest'
import { searchConversations } from './searchPackets'
import type { Conversation, Packet } from '../model/types'

function pkt(n: number, extra: Partial<Packet>): Packet {
  return { number: n, time: n / 10, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', srcPort: 1234, dstIp: '2.2.2.2', dstPort: 80, direction: 'other', ...extra }
}

describe('searchConversations', () => {
  it('info/URI/DNS 字段子串匹配,大小写不敏感', () => {
    const conv: Conversation = {
      id: 'k', client: 'a', server: 'b', protocol: 'http', packetCount: 3, bytes: 180,
      start: 0, end: 0.2, duration: 0.2, packets: [], issues: [],
    }
    conv.packets = [pkt(1, { info: 'HTTP GET /login' }), pkt(2, { httpUri: '/API/V1', httpMethod: 'GET' }), pkt(3, { dnsQuery: 'Example.COM' })]
    expect(searchConversations([conv], 'get').map((m) => m.numbers)).toEqual([[1]])
    expect(searchConversations([conv], '/api').map((m) => m.numbers)).toEqual([[2]])
    expect(searchConversations([conv], 'example.com').map((m) => m.numbers)).toEqual([[3]])
  })

  it('按端口/地址匹配', () => {
    const conv: Conversation = {
      id: 'k', client: 'a', server: 'b', protocol: 'http', packetCount: 2, bytes: 120,
      start: 0, end: 0.1, duration: 0.1, packets: [pkt(1, {}), pkt(2, { dstIp: '10.9.8.7', srcPort: 9999 })], issues: [],
    }
    expect(searchConversations([conv], '1234').map((m) => m.numbers)).toEqual([[1]])
    expect(searchConversations([conv], '10.9.8').map((m) => m.numbers)).toEqual([[2]])
  })

  it('空查询/无命中返回空', () => {
    const conv: Conversation = {
      id: 'k', client: 'a', server: 'b', protocol: 'tcp', packetCount: 1, bytes: 60,
      start: 0, end: 0, duration: 0, packets: [pkt(1, { info: 'TCP SYN' })], issues: [],
    }
    expect(searchConversations([conv], '  ')).toEqual([])
    expect(searchConversations([conv], 'zzz')).toEqual([])
  })

  it('多会话各返回自己的命中号', () => {
    const c1: Conversation = {
      id: 'k1', client: 'a', server: 'b', protocol: 'dns', packetCount: 1, bytes: 60,
      start: 0, end: 0, duration: 0, packets: [pkt(1, { proto: 'dns', dnsQuery: 'www.x.com' })], issues: [],
    }
    const c2: Conversation = {
      id: 'k2', client: 'a', server: 'b', protocol: 'dns', packetCount: 1, bytes: 60,
      start: 0, end: 0, duration: 0, packets: [pkt(2, { proto: 'dns', dnsQuery: 'www.x.com' }), pkt(3, { proto: 'dns', dnsQuery: 'www.y.net' })], issues: [],
    }
    const hits = searchConversations([c1, c2], 'x.com')
    expect(hits.map((h) => [h.convId, h.numbers])).toEqual([['k1', [1]], ['k2', [2]]])
  })

  it('同一会话二次搜索命中 WeakMap 缓存路径,不同关键词结果正确且不抛错', () => {
    const conv: Conversation = {
      id: 'k', client: 'a', server: 'b', protocol: 'http', packetCount: 2, bytes: 120,
      start: 0, end: 0.1, duration: 0.1,
      packets: [pkt(1, { info: 'HTTP GET /alpha' }), pkt(2, { dnsQuery: 'beta.example.com' })],
      issues: [],
    }
    // 首次搜索构建并缓存 haystack
    expect(searchConversations([conv], 'alpha').map((m) => m.numbers)).toEqual([[1]])
    // 同一 conv 复用缓存,不同关键词各自命中
    expect(searchConversations([conv], 'beta').map((m) => m.numbers)).toEqual([[2]])
    expect(searchConversations([conv], 'example').map((m) => m.numbers)).toEqual([[2]])
    // 缓存路径下无命中也不抛错
    expect(searchConversations([conv], 'zzz')).toEqual([])
  })
})
