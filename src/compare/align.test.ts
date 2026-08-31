import { describe, expect, it } from 'vitest'
import { alignConversations } from './align'
import type { Conversation, Packet } from '../model/types'

/** 手工构造会话(与 analyzeTcp 相关测试同风格,不依赖 tshark):
 *  只填对照引擎实际消费的字段,其余用最小合法值占位。 */
function mkConv(opts: {
  id: string
  transport?: 'tcp' | 'udp' | 'icmp' | 'arp' | 'other'
  aIp: string
  aPort: number
  bIp: string
  bPort: number
  start: number
  end: number
  count: number
}): Conversation {
  const transport = opts.transport ?? 'tcp'
  const packets: Packet[] = []
  for (let i = 0; i < opts.count; i++) {
    const fromA = i % 2 === 0
    const t = opts.start + (opts.end - opts.start) * (i / Math.max(1, opts.count - 1))
    packets.push({
      number: i + 1,
      time: t,
      timeEpoch: 1700000000 + t,
      len: 100,
      transport,
      proto: transport,
      srcIp: fromA ? opts.aIp : opts.bIp,
      dstIp: fromA ? opts.bIp : opts.aIp,
      srcPort: fromA ? opts.aPort : opts.bPort,
      dstPort: fromA ? opts.bPort : opts.aPort,
      info: '',
      direction: fromA ? 'request' : 'response',
    })
  }
  return {
    id: opts.id,
    client: `${opts.aIp}:${opts.aPort}`,
    server: `${opts.bIp}:${opts.bPort}`,
    protocol: transport,
    packetCount: opts.count,
    bytes: opts.count * 100,
    start: opts.start,
    end: opts.end,
    duration: opts.end - opts.start,
    packets,
    issues: [],
  }
}

describe('alignConversations', () => {
  it('pairs two conversations with same endpoint pair regardless of tcp.stream', () => {
    // 两侧 tcp.stream 编号必然不同(A 侧 0,B 侧 7):匹配键不得含 stream
    const a = mkConv({ id: 'tcp|1.1.1.1:1000|2.2.2.2:80|s0', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 1, count: 4 })
    const b = mkConv({ id: 'tcp|1.1.1.1:1000|2.2.2.2:80|s7', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0.5, end: 1.5, count: 4 })
    const r = alignConversations([a], [b])
    expect(r.pairs).toHaveLength(1)
    expect(r.pairs[0].sideA.id).toBe(a.id)
    expect(r.pairs[0].sideB.id).toBe(b.id)
    expect(r.unmatched).toHaveLength(0)
  })

  it('matches endpoint pair symmetrically (direction of capture does not matter)', () => {
    // 同一条流,抓包侧不同导致 src/dst 主客互换:归一化端点对后仍应配上
    const a = mkConv({ id: 'a1', aIp: '10.0.0.2', aPort: 3389, bIp: '10.0.0.5', bPort: 2000, start: 0, end: 1, count: 2 })
    const b = mkConv({ id: 'b1', aIp: '10.0.0.5', aPort: 2000, bIp: '10.0.0.2', bPort: 3389, start: 0, end: 1, count: 2 })
    const r = alignConversations([a], [b])
    expect(r.pairs).toHaveLength(1)
  })

  it('splits by transport: tcp and udp conversations with same endpoints do not match', () => {
    const a = mkConv({ id: 'tcp', transport: 'tcp', aIp: '1.1.1.1', aPort: 53, bIp: '2.2.2.2', bPort: 53, start: 0, end: 1, count: 2 })
    const b = mkConv({ id: 'udp', transport: 'udp', aIp: '1.1.1.1', aPort: 53, bIp: '2.2.2.2', bPort: 53, start: 0, end: 1, count: 2 })
    const r = alignConversations([a], [b])
    expect(r.pairs).toHaveLength(0)
    expect(r.unmatched.map((u) => u.conv.id).sort()).toEqual(['tcp', 'udp'])
  })

  it('reports unmatched sides when endpoint pair exists only on one side', () => {
    const a1 = mkConv({ id: 'a-only', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 1, count: 6 })
    const b1 = mkConv({ id: 'b-other', aIp: '3.3.3.3', aPort: 1000, bIp: '4.4.4.4', bPort: 80, start: 0, end: 1, count: 3 })
    const r = alignConversations([a1], [b1])
    expect(r.pairs).toHaveLength(0)
    expect(r.unmatched).toEqual([
      { side: 'A', conv: a1 },
      { side: 'B', conv: b1 },
    ])
  })

  it('greedily pairs multiple same-key flows by time overlap then packet-count ratio', () => {
    // 同端点对两条流:A 侧 f1 长且包多、f2 短且包少;B 侧同样。贪心应交叉配对
    // (f1↔F1 重叠度高、包数比例 1:1;f2↔F2 同理),而不是顺序配对。
    const aF1 = mkConv({ id: 'a-f1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 100 })
    const aF2 = mkConv({ id: 'a-f2', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 20, end: 21, count: 4 })
    const bF1 = mkConv({ id: 'b-F1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 1, end: 11, count: 100 })
    const bF2 = mkConv({ id: 'b-F2', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 20.2, end: 21, count: 4 })
    const r = alignConversations([aF1, aF2], [bF1, bF2])
    expect(r.pairs).toHaveLength(2)
    const byA = new Map(r.pairs.map((p) => [p.sideA.id, p.sideB.id]))
    expect(byA.get('a-f1')).toBe('b-F1')
    expect(byA.get('a-f2')).toBe('b-F2')
  })

  it('leaves surplus flows unmatched when counts differ on the two sides', () => {
    const a1 = mkConv({ id: 'a1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 50 })
    const a2 = mkConv({ id: 'a2', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 40 })
    const b1 = mkConv({ id: 'b1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 45 })
    const r = alignConversations([a1, a2], [b1])
    expect(r.pairs).toHaveLength(1)
    // 未配上的是包数较少的 a2(包数比例劣于 a1)
    expect(r.unmatched).toEqual([{ side: 'A', conv: a2 }])
  })

  it('sorts pairs by endpoint-pair lexicographic order and unmatched by packet count desc', () => {
    const aZ = mkConv({ id: 'a-z', aIp: '9.9.9.9', aPort: 1, bIp: '9.9.9.9', bPort: 2, start: 0, end: 1, count: 2 })
    const aA = mkConv({ id: 'a-a', aIp: '1.1.1.1', aPort: 1, bIp: '2.2.2.2', bPort: 2, start: 0, end: 1, count: 2 })
    const bZ = mkConv({ id: 'b-z', aIp: '9.9.9.9', aPort: 1, bIp: '9.9.9.9', bPort: 2, start: 0, end: 1, count: 2 })
    const bA = mkConv({ id: 'b-a', aIp: '1.1.1.1', aPort: 1, bIp: '2.2.2.2', bPort: 2, start: 0, end: 1, count: 2 })
    const aSoloBig = mkConv({ id: 'a-big', aIp: '5.5.5.5', aPort: 1, bIp: '6.6.6.6', bPort: 2, start: 0, end: 1, count: 30 })
    const aSoloSmall = mkConv({ id: 'a-small', aIp: '5.5.5.5', aPort: 3, bIp: '6.6.6.6', bPort: 4, start: 0, end: 1, count: 5 })
    const r = alignConversations([aZ, aA, aSoloBig, aSoloSmall], [bZ, bA])
    expect(r.pairs.map((p) => p.sideA.id)).toEqual(['a-a', 'a-z'])
    expect(r.unmatched.map((u) => `${u.side}:${u.conv.id}`)).toEqual(['A:a-big', 'A:a-small'])
  })

  it('is deterministic: same input twice yields identical output', () => {
    const a = mkConv({ id: 'a1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 10 })
    const b = mkConv({ id: 'b1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 10, count: 10 })
    const r1 = alignConversations([a], [b])
    const r2 = alignConversations([a], [b])
    expect(JSON.stringify(r1)).toBe(JSON.stringify(r2))
  })

  it('handles empty sides', () => {
    const a = mkConv({ id: 'a1', aIp: '1.1.1.1', aPort: 1000, bIp: '2.2.2.2', bPort: 80, start: 0, end: 1, count: 2 })
    expect(alignConversations([], []).pairs).toHaveLength(0)
    expect(alignConversations([a], []).unmatched).toEqual([{ side: 'A', conv: a }])
    expect(alignConversations([], [a]).unmatched).toEqual([{ side: 'B', conv: a }])
  })
})
