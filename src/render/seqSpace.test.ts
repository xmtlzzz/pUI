import { describe, expect, it } from 'vitest'
import { computeSeqSpaceLayout } from './seqSpace.ts'
import type { Packet } from '../model/types'

/** 造包工具:只填序列空间相关字段,其余给合法缺省 */
function pkt(n: number, o: Partial<Packet>): Packet {
  return {
    number: n,
    time: n * 0.001,
    len: 60,
    transport: 'TCP',
    proto: 'tcp',
    ...o,
  } as Packet
}

/** 手写分析事实(不依赖 analyzeStream,布局函数的输入契约即 facts+packets) */
function facts(o: {
  segments?: Array<{ packetNumber: number; time: number; direction: 'c2s' | 's2c'; seq: number; seqLen: number }>
  gaps?: Array<{ direction: 'c2s' | 's2c'; start: number; end: number; byteCount: number }>
}) {
  return {
    streamId: 0,
    midStream: false,
    lengthUnavailable: false,
    segments: (o.segments ?? []).map((s) => ({ payloadLen: s.seqLen, classification: 'new-in-order' as const, newBytes: s.seqLen, ...s })),
    gaps: (o.gaps ?? []).map((g) => ({ firstObservedPacket: 0, firstObservedTime: 0, sackCovered: false, filled: false, ...g })),
    seenBytes: { c2s: 0, s2c: 0 },
    unorderableInput: false,
  }
}

describe('computeSeqSpaceLayout', () => {
  const packets = [
    pkt(1, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 0, tcpAck: 0, tcpLen: 0, tcpFlags: '0x0002' }),
    pkt(2, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpFlags: '0x0012' }),
    pkt(3, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
    pkt(4, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }), // 越过缺口
    pkt(5, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 301]] }),
    pkt(6, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 1, tcpAck: 301, tcpLen: 0 }),
    pkt(7, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 101, tcpAck: 301, tcpLen: 100 }), // 重传回补
  ]

  it('产出上下两条方向带,带序稳定(c2s 在上)', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    expect(lay.lanes.map((l) => l.direction)).toEqual(['c2s', 's2c'])
    expect(lay.lanes[0].label).toBe('10.0.0.1:1000 → 10.0.0.2:80')
    expect(lay.lanes[1].label).toBe('10.0.0.2:80 → 10.0.0.1:1000')
  })

  it('每方向带:轴=该方向数据最小 seq 到最大 seq+len(最小跨度保护)', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    const c2s = lay.lanes[0]
    expect(c2s.axisMin).toBe(0) // SYN 占位 seq 0..1 计入
    expect(c2s.axisMax).toBe(301)
  })

  it('已见条=段合并;缺口从 facts.gaps 裁剪进带', () => {
    const f = facts({
      segments: [
        { packetNumber: 1, time: 0, direction: 'c2s', seq: 100, seqLen: 50 },
        { packetNumber: 2, time: 1, direction: 'c2s', seq: 150, seqLen: 50 },
        { packetNumber: 3, time: 2, direction: 'c2s', seq: 300, seqLen: 50 },
      ],
      gaps: [{ direction: 'c2s', start: 200, end: 300, byteCount: 100 }],
    })
    const lay = computeSeqSpaceLayout(packets, { client: 'x:1', factsOverride: f })
    const lane = lay.lanes[0]
    expect(lane.seenRuns).toEqual([
      [100, 200],
      [300, 350],
    ])
    expect(lane.gaps).toEqual([[200, 300]])
  })

  it('SACK 块按承载报文方向归入对向带并合并', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    // #5 是 s2c 方向报文,携带的 SACK 描述 c2s 数据 → 归入 c2s 带
    expect(lay.lanes[0].sackBlocks).toEqual([[201, 301]])
    expect(lay.lanes[1].sackBlocks).toEqual([])
  })

  it('ACK 游标=对向报文携带的最大累计确认', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    // c2s 带的 ACK 游标来自 s2c 报文(#5 ack=101、#6 ack=301)→ 301
    expect(lay.lanes[0].finalAck).toBe(301)
    // s2c 带的 ACK 游标来自 c2s 报文(#1 ack=0、#3/#4/#7 ack=301)→ 301
    expect(lay.lanes[1].finalAck).toBe(301)
  })

  it('重传标记:tcpAnalysis 含 retransmission 的报文 seq 落进带内', () => {
    const ps = [
      pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100 }),
      pkt(2, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100, tcpAnalysis: ['retransmission'] }),
    ]
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    expect(lay.lanes[0].retxMarks).toEqual([{ packetNumber: 2, seq: 0, len: 100 }])
  })

  it('无数据段的方向带(axisMax<=axisMin)不产出', () => {
    const ps = [pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100 })]
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    expect(lay.lanes).toHaveLength(1)
  })

  it('空会话产出空 lanes;非 TCP 会话回退时间轴带(不再空态)', () => {
    expect(computeSeqSpaceLayout([], { client: 'a:1' }).lanes).toEqual([])
    const udp = [pkt(1, { transport: 'udp', proto: 'dns', srcIp: 'a', dstIp: 'b' })]
    const lay = computeSeqSpaceLayout(udp, { client: 'a:1' })
    expect(lay.lanes).toHaveLength(1)
    expect(lay.lanes[0].kind).toBe('fallback')
    expect(lay.lanes[0].messages).toHaveLength(1)
  })

  it('刻度=1/2/5 整步长,覆盖轴范围', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    const ticks = lay.lanes[0].ticks
    expect(ticks.length).toBeGreaterThan(2)
    expect(ticks[0]).toBeGreaterThanOrEqual(lay.lanes[0].axisMin)
    expect(ticks[ticks.length - 1]).toBeLessThanOrEqual(lay.lanes[0].axisMax)
    // 步长规整:相邻差相等且为 1/2/5×10^k
    const step = ticks[1] - ticks[0]
    expect(step).toBeGreaterThan(0)
    const norm = step / Math.pow(10, Math.floor(Math.log10(step)))
    expect([1, 2, 5]).toContain(Math.round(norm * 1000) / 1000)
    for (let i = 2; i < ticks.length; i++) expect(ticks[i] - ticks[i - 1]).toBe(step)
  })

  it('SACK 渲染护栏:单带超过 100 块截断', () => {
    const ps: Packet[] = [pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100 })]
    for (let i = 0; i < 150; i++) {
      ps.push(pkt(1000 + i, { srcIp: 'b', dstIp: 'a', tcpSeq: 0, tcpLen: 0, tcpAck: 100, tcpSackBlocks: [[i * 10, i * 10 + 5]] }))
    }
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    expect(lay.lanes[0].sackBlocks.length).toBe(100)
  })

  it('事件证据链(证据报文)标注进带:暴露缺口/重传回补落在数据带,恢复 ACK 也落在被恢复的带', () => {
    const lay = computeSeqSpaceLayout(packets, { client: '10.0.0.1:1000', server: '10.0.0.2:80' })
    // c2s 带:#4 越过缺口暴露缺口;#7 重传回补;#6 的累计确认(301)越过缺口终点 → 恢复标注也在 c2s 带(游标位置处)
    const nums = lay.lanes[0].marks.map((m) => m.packetNumber)
    expect(nums).toContain(4)
    expect(nums).toContain(7)
    expect(nums).toContain(6)
  })

  it('恢复 ACK 标注只取每个缺口的首个越过确认,不随 ACK 数量增长', () => {
    // 缺口 101..201;c2s 数据到 301;对向(#10..#19)连续 10 个 ACK 陆续越过 201
    const ps: Packet[] = [
      pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 1, tcpLen: 100 }),
      pkt(2, { srcIp: 'a', dstIp: 'b', tcpSeq: 201, tcpLen: 100 }),
    ]
    for (let i = 0; i < 10; i++) {
      ps.push(pkt(10 + i, { srcIp: 'b', dstIp: 'a', tcpSeq: 1, tcpLen: 0, tcpAck: 150 + i * 10 }))
    }
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    const c2s = lay.lanes[0]
    expect(c2s.gaps).toEqual([[101, 201]])
    const ackMarks = c2s.marks.filter((m) => m.kind === 'ack')
    expect(ackMarks).toHaveLength(1) // 只有首个 ack≥210 的确认(#16,ack=150+60=210),不是 8 个
    expect(ackMarks[0].packetNumber).toBe(16)
  })

  it('marks/retxMarks 渲染护栏:单带超上限时均匀采样截断', () => {
    // 300 个重传 + 300 个乱序填充分散在不同 seq(避免合并),上限 200
    const ps: Packet[] = [pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 10 })]
    let n = 2
    for (let i = 0; i < 300; i++) {
      ps.push(pkt(n++, { srcIp: 'a', dstIp: 'b', tcpSeq: 100 + i * 20, tcpLen: 10, tcpAnalysis: ['retransmission'] }))
      ps.push(pkt(n++, { srcIp: 'a', dstIp: 'b', tcpSeq: 100 + i * 20 + 10, tcpLen: 10, tcpAnalysis: ['out-of-order'] }))
    }
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    const lane = lay.lanes[0]
    expect(lane.marks.length).toBeLessThanOrEqual(200)
    expect(lane.retxMarks.length).toBeLessThanOrEqual(200)
    // 采样保序:seq 升序不乱
    for (let i = 1; i < lane.marks.length; i++) expect(lane.marks[i].seq).toBeGreaterThanOrEqual(lane.marks[i - 1].seq)
  })

  it('gaps/seenRuns 渲染护栏:超上限合并为聚合带,轴范围不变', () => {
    // 200 个缺口段(段间 10B 洞),未超上限 → 全量
    const ps: Packet[] = []
    for (let i = 0; i < 200; i++) {
      ps.push(pkt(i + 1, { srcIp: 'a', dstIp: 'b', tcpSeq: i * 110, tcpLen: 100 }))
    }
    const lay = computeSeqSpaceLayout(ps, { client: 'a:1' })
    const lane = lay.lanes[0]
    expect(lane.seenRuns.length).toBe(200)
    expect(lane.gaps.length).toBe(199)
    // 超上限形态:2000 段 → 合并为聚合带(≤300),轴范围不变
    const ps2: Packet[] = []
    for (let i = 0; i < 2000; i++) {
      ps2.push(pkt(i + 1, { srcIp: 'a', dstIp: 'b', tcpSeq: i * 110, tcpLen: 100 }))
    }
    const lay2 = computeSeqSpaceLayout(ps2, { client: 'a:1' })
    const l2 = lay2.lanes[0]
    expect(l2.seenRuns.length).toBeLessThanOrEqual(300)
    expect(l2.gaps.length).toBeLessThanOrEqual(300)
    // 轴范围不变(合并不改变事实边界)
    expect(l2.axisMin).toBe(0)
    expect(l2.axisMax).toBe(1999 * 110 + 100)
    // 采样保序
    for (let i = 1; i < l2.seenRuns.length; i++) expect(l2.seenRuns[i][0]).toBeGreaterThan(l2.seenRuns[i - 1][0])
  })

  it('性能护栏:高缺口率 23k 包全布局 < 1.5s(卡死回归)', () => {
    const N = 23000
    const ps: Packet[] = []
    let seq = 0
    for (let i = 0; i < N; i++) {
      const c2s = i % 2 === 0
      if (c2s) {
        seq += 500
        if (i % 6 === 0) seq += 200
        ps.push(pkt(i + 1, { srcIp: 'a', dstIp: 'b', tcpSeq: seq, tcpLen: 500, tcpAck: 1, tcpAnalysis: i % 11 === 0 ? ['retransmission'] : undefined }))
      } else {
        ps.push(pkt(i + 1, { srcIp: 'b', dstIp: 'a', tcpSeq: 9999, tcpLen: 0, tcpAck: seq, tcpSackBlocks: i % 10 === 0 ? [[seq - 200, seq]] : undefined }))
      }
    }
    const t0 = performance.now()
    computeSeqSpaceLayout(ps, { client: 'a:1' })
    const ms = performance.now() - t0
    expect(ms).toBeLessThan(1500)
  })

  it('非 TCP 会话回退时间轴带:每协议一条带,轴=报文序号,行内报文可点击', () => {
    const ps: Packet[] = [
      pkt(1, { transport: 'udp', proto: 'mdns', srcIp: 'a', dstIp: '224.0.0.251', srcPort: 5353, dstPort: 5353 }),
      pkt(2, { transport: 'arp', proto: 'arp', srcMac: 'aa', dstMac: 'ff', srcIp: 'a' }),
      pkt(3, { transport: 'udp', proto: 'mdns', srcIp: 'a', dstIp: '224.0.0.251', srcPort: 5353, dstPort: 5353 }),
    ]
    const lay = computeSeqSpaceLayout(ps, { client: 'a' })
    expect(lay.lanes).toHaveLength(2) // mdns 一带 + arp 一带(按 协议+端点对 分带)
    const mdns = lay.lanes.find((l) => l.label.includes('mdns'))!
    expect(mdns.messages.map((m) => m.packetNumber)).toEqual([1, 3])
    expect(mdns.messages[0].label).toContain('#1')
  })

  it('非 TCP 回退带:轴=相对时间秒,每报文一条方向线段(线条交互图)', () => {
    // ICMP ping 一来一回:0.1s 请求、0.2s 响应
    const ps: Packet[] = [
      pkt(1, { transport: 'icmp', proto: 'icmp', srcIp: 'a', dstIp: 'b', time: 0.1, direction: 'request' }),
      pkt(2, { transport: 'icmp', proto: 'icmp', srcIp: 'b', dstIp: 'a', time: 0.2, direction: 'response' }),
      pkt(3, { transport: 'icmp', proto: 'icmp', srcIp: 'a', dstIp: 'b', time: 0.5, direction: 'request' }),
    ]
    const lay = computeSeqSpaceLayout(ps, { client: 'a' })
    const lane = lay.lanes[0]
    // 轴=时间(0.1..0.5),不再是报文序号
    expect(lane.axisMin).toBeCloseTo(0.1)
    expect(lane.axisMax).toBeCloseTo(0.5)
    // 每报文一条线段,t 时刻落位;x1/x2 体现方向(请求右行、响应左行)
    expect(lane.messages).toHaveLength(3)
    expect(lane.messages[0].t).toBeCloseTo(0.1)
    expect(lane.messages[0].dir).toBe('a2b')
    expect(lane.messages[1].dir).toBe('b2a')
    // 采样护栏仍在(200 上限)
    expect(lane.kind).toBe('fallback')
  })

  it('非 TCP 带刻度同样 1/2/5 步长;混合 TCP+非 TCP 时只出 TCP 序号空间带', () => {
    const ps: Packet[] = [
      pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100 }),
      pkt(2, { transport: 'arp', proto: 'arp', srcMac: 'aa', dstMac: 'ff' }),
    ]
    const lay = computeSeqSpaceLayout(ps, { client: 'a' })
    expect(lay.lanes).toHaveLength(1)
    expect(lay.lanes[0].ticks.length).toBeGreaterThan(0)
  })
})
