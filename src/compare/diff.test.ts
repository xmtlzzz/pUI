import { describe, expect, it } from 'vitest'
import { diffConversations } from './diff'
import type { CompareTcpEvent, CompareFacts } from './diff'
import type { AppEvent } from '../analysis/app/analyzers'
import type { Conversation, Packet } from '../model/types'

/** 手工构造报文(参考 analyzeTcp 相关测试风格,不依赖 tshark) */
function pkt(n: number, tEpoch: number, opts: {
  len?: number
  fromA: boolean
  ipA: string
  ipB: string
  portA: number
  portB: number
  info?: string
}): Packet {
  return {
    number: n,
    time: tEpoch,
    timeEpoch: tEpoch,
    len: opts.len ?? 100,
    transport: 'tcp',
    proto: 'tcp',
    srcIp: opts.fromA ? opts.ipA : opts.ipB,
    dstIp: opts.fromA ? opts.ipB : opts.ipA,
    srcPort: opts.fromA ? opts.portA : opts.portB,
    dstPort: opts.fromA ? opts.portB : opts.portA,
    info: opts.info ?? '',
    direction: opts.fromA ? 'request' : 'response',
  }
}

function mkConv(packets: Packet[], id: string): Conversation {
  const start = packets[0]?.time ?? 0
  const end = packets[packets.length - 1]?.time ?? 0
  return {
    id,
    client: '',
    server: '',
    protocol: 'tcp',
    packetCount: packets.length,
    bytes: packets.reduce((s, p) => s + p.len, 0),
    start,
    end,
    duration: end - start,
    packets,
    issues: [],
  }
}

/** 缺口类 TcpEvent 最小构造:只带 diff 消费的窄字段(时间不参与事件判定键,故窄接口不含) */
function gapEvent(kind: CompareTcpEvent['kind'], start: number, end: number, recovered: boolean): CompareTcpEvent {
  return { kind, recovered, gap: { start, end, byteCount: end - start } }
}

describe('diffConversations · stats', () => {
  it('computes packet count and byte deltas per side', () => {
    const aPkts = [pkt(1, 100.0, { fromA: true, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80 }), pkt(2, 100.01, { fromA: false, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80, len: 200 })]
    const bPkts = [pkt(1, 100.0, { fromA: true, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80 })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    expect(d.stats).toEqual({ countA: 2, countB: 1, bytesA: 300, bytesB: 100 })
  })
})

describe('diffConversations · eventDiffs', () => {
  it('marks event seen on both sides as both when kind and rounded gap match', () => {
    // 同一缺口:两侧 raw 序号理论同值,小数残留(如经换算的合成值)四舍五入后应落同一整数键
    // (999.6/1000.4 均取整为 1000;1500.6/1500.5 均为 1501)
    const eA = gapEvent('possible-loss-or-delay', 999.6, 1500.6, true)
    const eB = gapEvent('possible-loss-or-delay', 1000.4, 1500.5, true)
    const d = diffConversations(conv1(), emptyFacts(), [eA], conv1(), emptyFacts(), [eB])
    expect(d.eventDiffs).toHaveLength(1)
    expect(d.eventDiffs[0]).toMatchObject({ kind: 'possible-loss-or-delay', onlyIn: 'both', recovered: true })
    // 展示文本按四舍五入整数归一(同一判定键取 A 侧文本)
    expect(d.eventDiffs[0].gapText).toBe('1000–1501')
  })

  it('marks event onlyIn A when B has no same-key event, carrying A gapText', () => {
    const eA = gapEvent('possible-loss-or-delay', 100, 200, false)
    const d = diffConversations(conv1(), emptyFacts(), [eA], conv1(), emptyFacts(), [])
    expect(d.eventDiffs).toHaveLength(1)
    expect(d.eventDiffs[0].onlyIn).toBe('A')
    expect(d.eventDiffs[0].recovered).toBe(false)
    expect(d.eventDiffs[0].gapText).toBe('100–200')
  })

  it('marks event onlyIn B symmetrically', () => {
    const eB: CompareTcpEvent = { kind: 'rst', recovered: true }
    const d = diffConversations(conv1(), emptyFacts(), [], conv1(), emptyFacts(), [eB])
    expect(d.eventDiffs).toEqual([{ kind: 'rst', gapText: undefined, recovered: true, onlyIn: 'B' }])
  })

  it('treats same kind with different rounded gap as distinct events', () => {
    const eA = gapEvent('possible-loss-or-delay', 100, 200, true)
    const eB = gapEvent('possible-loss-or-delay', 300, 400, true)
    const d = diffConversations(conv1(), emptyFacts(), [eA], conv1(), emptyFacts(), [eB])
    expect(d.eventDiffs.map((e) => e.onlyIn).sort()).toEqual(['A', 'B'])
  })

  it('merges app events into the same keyed space with gapless key', () => {
    const appA: AppEvent = { id: 'http:request:1', app: 'http', kind: 'request', packetNumber: 1, time: 1, summary: 'HTTP GET /a' }
    const appB: AppEvent = { id: 'http:request:2', app: 'http', kind: 'request', packetNumber: 2, time: 1, summary: 'HTTP GET /a' }
    const d = diffConversations(conv1(), emptyFacts(), [appA], conv1(), emptyFacts(), [appB])
    expect(d.eventDiffs).toHaveLength(1)
    expect(d.eventDiffs[0].onlyIn).toBe('both')
    expect(d.eventDiffs[0].kind).toBe('http:request')
  })
})

describe('diffConversations · timeline', () => {
  const ipA = '1.1.1.1'
  const ipB = '2.2.2.2'
  const portA = 1000
  const portB = 80

  it('merges request+response within tolerance into one AB row keeping both infos', () => {
    // 同一交互两侧视角:A 侧只见请求,B 侧只见响应,epoch 差 1ms ≤ 2ms 容差
    const aPkts = [pkt(1, 100.000, { fromA: true, ipA, ipB, portA, portB, info: 'GET /x' })]
    const bPkts = [pkt(1, 100.001, { fromA: false, ipA, ipB, portA, portB, info: '200 OK' })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    expect(d.timeline).toHaveLength(1)
    const row = d.timeline[0]
    expect(row.side).toBe('AB')
    expect(row.infoA).toBe('GET /x')
    expect(row.infoB).toBe('200 OK')
    expect(row.numberA).toBe(1)
    expect(row.numberB).toBe(1)
    expect(d.truncated).toBe(false)
  })

  it('keeps sides separate when epoch gap exceeds tolerance', () => {
    const aPkts = [pkt(1, 100.000, { fromA: true, ipA, ipB, portA, portB, info: 'GET /x' })]
    const bPkts = [pkt(1, 100.010, { fromA: false, ipA, ipB, portA, portB, info: '200 OK' })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    expect(d.timeline.map((r) => r.side)).toEqual(['A', 'B'])
  })

  it('does not merge same-direction packets even within tolerance (A-only retransmission seen twice)', () => {
    // 同方向两包不构成「一请求一响应」,即使 epoch 落在容差内也不合并
    const aPkts = [pkt(1, 100.000, { fromA: true, ipA, ipB, portA, portB, info: 'seq=1' })]
    const bPkts = [pkt(1, 100.001, { fromA: true, ipA, ipB, portA, portB, info: 'seq=1 dup' })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    expect(d.timeline.map((r) => r.side)).toEqual(['A', 'B'])
  })

  it('marks only-in-one-side rows with omitted opposite frame number', () => {
    const aPkts = [pkt(7, 100.0, { fromA: true, ipA, ipB, portA, portB, info: 'only on A' })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv([], 'b'), emptyFacts(), [])
    expect(d.timeline[0].side).toBe('A')
    expect(d.timeline[0].numberA).toBe(7)
    expect('numberB' in d.timeline[0]).toBe(false) // 仅 A 见到时 B 侧帧号整体省略(非 undefined 残留)
    expect('infoB' in d.timeline[0]).toBe(false)
  })

  it('respects custom epoch tolerance option', () => {
    const aPkts = [pkt(1, 100.000, { fromA: true, ipA, ipB, portA, portB })]
    const bPkts = [pkt(1, 100.005, { fromA: false, ipA, ipB, portA, portB })]
    const strict = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), []) // 默认 2ms:不合并
    expect(strict.timeline.map((r) => r.side)).toEqual(['A', 'B'])
    const loose = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [], { epochToleranceMs: 10 })
    expect(loose.timeline.map((r) => r.side)).toEqual(['AB'])
  })

  it('sorts timeline by timeEpoch ascending', () => {
    const aPkts = [pkt(1, 100.002, { fromA: true, ipA, ipB, portA, portB }), pkt(2, 100.0, { fromA: true, ipA, ipB, portA, portB })]
    const bPkts = [pkt(1, 100.001, { fromA: false, ipA, ipB, portA, portB })]
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    const times = d.timeline.map((r) => r.timeEpoch)
    expect([...times].sort((x, y) => x - y)).toEqual(times)
  })

  it('truncates timeline beyond 2000 rows and sets truncated flag', () => {
    // 两侧各 1200 包、epoch 全错开(不合并 AB):总行数 2400 > 2000 → 截断
    const aPkts: Packet[] = []
    for (let i = 0; i < 1200; i++) aPkts.push(pkt(i + 1, 100 + i * 0.001, { fromA: true, ipA, ipB, portA, portB }))
    const bPkts: Packet[] = []
    for (let i = 0; i < 1200; i++) bPkts.push(pkt(i + 1, 100 + i * 0.01 + 0.05, { fromA: false, ipA, ipB, portA, portB }))
    const d = diffConversations(mkConv(aPkts, 'a'), emptyFacts(), [], mkConv(bPkts, 'b'), emptyFacts(), [])
    expect(d.truncated).toBe(true)
    expect(d.timeline).toHaveLength(2000)
    // 截断按时间升序保留最早的 2000 行
    const times = d.timeline.map((r) => r.timeEpoch)
    expect([...times].sort((x, y) => x - y)).toEqual(times)
  })
})

describe('diffConversations · determinism & injection safety', () => {
  it('is deterministic: two calls produce identical JSON', () => {
    const aPkts = [pkt(1, 100.0, { fromA: true, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80, info: '<img src=x onerror=alert(1)>' })]
    const bPkts = [pkt(1, 100.001, { fromA: false, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80, info: '<script>x</script>' })]
    const eA = gapEvent('possible-loss-or-delay', 100, 200, false)
    const argA = mkConv(aPkts, 'a')
    const argB = mkConv(bPkts, 'b')
    const d1 = diffConversations(argA, emptyFacts(), [eA], argB, emptyFacts(), [])
    const d2 = diffConversations(argA, emptyFacts(), [eA], argB, emptyFacts(), [])
    expect(JSON.stringify(d1)).toBe(JSON.stringify(d2))
    // 注入字段原样进入模型(转义是渲染层职责),diff 层不丢不改
    expect(d1.timeline[0].infoA).toContain('onerror')
  })
})

// ---- 测试辅助:最小 Conversation / facts ----

function conv1(): Conversation {
  const p = pkt(1, 100.0, { fromA: true, ipA: '1.1.1.1', ipB: '2.2.2.2', portA: 1000, portB: 80 })
  return mkConv([p], 'c')
}

function emptyFacts(): CompareFacts {
  return { midStream: false }
}
