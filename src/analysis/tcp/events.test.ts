import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import { detectTcpEvents } from './events'
import { analyzeStream } from './streamAnalysis'

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: (o.tcpLen ?? 0) + 54,
    direction: 'other',
    tcpStream: 0,
    ...o,
  } as Packet
}
const c2s = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
const s2c = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })

const SYN = '0x0002'
const SYNACK = '0x0012'
const ACK = '0x0010'
const PSHACK = '0x0018'

const handshake = () => [
  c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0, tcpCompleteness: 15 }),
  s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15 }),
  c2s({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpLen: 0, tcpCompleteness: 15 }),
]

const run = (packets: Packet[]) => detectTcpEvents(analyzeStream(packets), packets)

/** 指南第 5 节的典型「疑似丢包」链:数据 → ACK 停滞 → Dup ACK → SACK → 重传 → ACK 前进 */
const lossChain = () => [
  ...handshake(),
  c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
  c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({
    number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 301]], tcpDupAckNum: 1, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  c2s({ number: 8, time: 0.07, tcpFlags: PSHACK, tcpSeq: 301, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
  s2c({
    number: 9, time: 0.08, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 401]], tcpDupAckNum: 2, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  s2c({
    number: 10, time: 0.09, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0,
    tcpSackBlocks: [[201, 401]], tcpDupAckNum: 3, tcpAnalysis: ['duplicate-ack'], tcpCompleteness: 15,
  }),
  c2s({
    number: 11, time: 0.25, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
    tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
  }),
  s2c({ number: 12, time: 0.26, tcpFlags: ACK, tcpSeq: 1, tcpAck: 401, tcpLen: 0, tcpCompleteness: 15 }),
]

describe('detectTcpEvents — 三类 MVP 事件', () => {
  it('疑似丢包/延迟到达:完整证据链被串成一个事件', () => {
    const evs = run(lossChain())
    expect(evs).toHaveLength(1)
    const e = evs[0]
    expect(e.kind).toBe('possible-loss-or-delay')
    expect(e.recovered).toBe(true)
    // 证据链必须能点回具体报文(指南第 10、11 节)
    expect(e.originalSegmentPacket).toBe(6) // 越过缺口到达、暴露空洞的段
    expect(e.retransmissionPacket).toBe(11)
    expect(e.recoveryAckPacket).toBe(12)
    expect(e.duplicateAckCount).toBe(3)
    expect(e.sackPresent).toBe(true)
    expect(e.gap).toMatchObject({ start: 101, end: 201, byteCount: 100 })
  })

  it('重复 ACK 折叠为一个计数,不按数组条目重复计数', () => {
    // 实测平铺模式下单个 dup ACK 报文的 duplicate_ack 值是 ["1","1"];
    // 事件里的计数必须按报文数(3),不能翻倍成 6
    const evs = run(lossChain())
    expect(evs[0].duplicateAckCount).toBe(3)
    expect(evs[0].duplicateAckPackets).toEqual([7, 9, 10])
  })

  it('推断必须引用证据,且证据都指向真实报文号', () => {
    const evs = run(lossChain())
    const e = evs[0]
    expect(e.inference.evidenceRefs.length).toBeGreaterThan(0)
    const numbers = new Set(lossChain().map((p) => p.number))
    for (const r of e.inference.evidenceRefs) {
      expect(numbers.has(r.packetNumber)).toBe(true)
    }
    // 观察与推断分离:observations 只陈述现象,inference 才给判断
    expect(e.observations.length).toBeGreaterThan(0)
    expect(e.inference.statement).toBeTruthy()
  })

  it('乱序补齐且无重传 → 归类为乱序,而非丢包', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      // B 迟到补齐;注意 tshark 会给它打 retransmission 标签(实测),但序列空间证明是新字节
      c2s({
        number: 6, time: 0.052, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
      }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].kind).toBe('reordering')
    expect(evs[0].recovered).toBe(true)
    expect(evs[0].retransmissionPacket).toBeUndefined() // 没有真正的重发
  })

  it('无 Gap 的重传 → 伪重传/可能 ACK 丢失,绝不判为确定性数据丢失', () => {
    // M3 验收线
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({
        number: 6, time: 0.3, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission', 'spurious-retransmission'], tcpCompleteness: 15,
      }),
      s2c({ number: 7, time: 0.31, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].kind).toBe('possible-ack-loss-or-spurious')
    // 不得出现"确定丢包"式表述
    expect(evs[0].inference.statement).not.toMatch(/确定|一定|肯定/)
    expect(evs[0].gap).toBeUndefined()
  })

  it('未填补的 Gap:标记未恢复,严重度更高', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].recovered).toBe(false)
    expect(evs[0].severity).toBe('high')
  })

  it('两个独立 Gap → 两个事件,id 稳定且排序确定', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.07, tcpFlags: PSHACK, tcpSeq: 401, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 7, time: 0.2, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
    ]
    const evs = run(packets)
    expect(evs).toHaveLength(2)
    // 未恢复的排前面(301..401 未补),已恢复的在后
    expect(evs[0].recovered).toBe(false)
    expect(evs[1].recovered).toBe(true)
    // id 只依赖流/方向/序列号/类型,与输入顺序无关
    const shuffled = run([...packets].reverse())
    expect(shuffled.map((e) => e.id).sort()).toEqual(evs.map((e) => e.id).sort())
  })

  it('事件 id 不随输入顺序变化(确定性)', () => {
    const a = run(lossChain())
    const b = run([...lossChain()].reverse())
    expect(b.map((e) => e.id)).toEqual(a.map((e) => e.id))
  })

  it('中途抓包:置信度下调并附加抓包限制说明', () => {
    const evs = run([
      c2s({ number: 1, time: 0, tcpFlags: PSHACK, tcpSeq: 500001, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
      c2s({ number: 2, time: 0.02, tcpFlags: PSHACK, tcpSeq: 500201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
      c2s({ number: 3, time: 0.2, tcpFlags: PSHACK, tcpSeq: 500101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].inference.confidence).toBe('low')
    expect(evs[0].limitations.some((l) => /中途|mid-stream/i.test(l))).toBe(true)
  })

  it('单侧观察点:限制说明中明确无法定位丢包位置', () => {
    const evs = run(lossChain())
    expect(evs[0].limitations.some((l) => /单.*观察|无法定位|具体位置/.test(l))).toBe(true)
  })

  it('正常连续传输不产生任何事件(零误报)', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 201, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toEqual([])
  })

  it('纯重复段(无 Gap、无 spurious 标签)也归为伪重传类而非丢包', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.3, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
    ])
    expect(evs.map((e) => e.kind)).toEqual(['possible-ack-loss-or-spurious'])
  })

  it('事件按「未恢复 → 证据完整度 → 持续时长」排序', () => {
    const evs = run(lossChain())
    // 单事件场景下至少要有可比较的评分字段
    expect(typeof evs[0].evidenceScore).toBe('number')
    expect(evs[0].evidenceScore).toBeGreaterThan(0)
  })

  it('序列化稳定:同一输入两次输出字节一致', () => {
    expect(JSON.stringify(run(lossChain()))).toBe(JSON.stringify(run(lossChain())))
  })

  it('观察项如实记录 tshark 标签,但不作为分类依据', () => {
    // 乱序场景里 tshark 打了 retransmission,分类结果仍是 reordering;
    // 该标签应出现在 observations 中(作为"观察到的现象")
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({
        number: 6, time: 0.052, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
      }),
    ])
    expect(evs[0].kind).toBe('reordering')
    const text = evs[0].observations.map((o) => o.statement).join(' ')
    expect(text).toMatch(/retransmission/)
  })
})

describe('detectTcpEvents — 填补分类器(classifyFill):启发信号必须落在事件上', () => {
  it('相邻交换:5ms 后由全新字节补齐、0 个重复 ACK → reordering/high,并记录分类信号', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({
        number: 6, time: 0.055, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100,
        tcpAnalysis: ['retransmission'], tcpCompleteness: 15,
      }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    const e = evs[0]
    expect(e.kind).toBe('reordering')
    expect(e.inference.confidence).toBe('high')
    // Why 面板数据契约:分类所依赖的信号必须可渲染,而不是藏在代码里的魔法数字
    expect(e.classificationSignals).toBeDefined()
    expect(e.classificationSignals!.fillerCarriesOnlyNewBytes).toBe(true)
    expect(e.classificationSignals!.duplicateAckCount).toBe(0)
    expect(e.classificationSignals!.durationSeconds).toBeCloseTo(0.005, 6)
    expect(e.rationale).toBeTruthy()
  })

  it('LAN 快重传形态:3 个重复 ACK、50ms 恢复 → possible-loss-or-delay/medium', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 6, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.07, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      s2c({ number: 8, time: 0.08, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 9, time: 0.1, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 10, time: 0.11, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].kind).toBe('possible-loss-or-delay')
    expect(evs[0].inference.confidence).toBe('medium')
    expect(evs[0].duplicateAckCount).toBe(3)
    expect(evs[0].classificationSignals?.duplicateAckCount).toBe(3)
  })

  it('RTO 形态:0-1 个重复 ACK、300ms 后补齐 → possible-loss-or-delay/medium', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 6, time: 0.35, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.36, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    expect(evs[0].kind).toBe('possible-loss-or-delay')
    expect(evs[0].inference.confidence).toBe('medium')
    expect(evs[0].duplicateAckCount).toBe(0)
    expect(evs[0].classificationSignals?.durationSeconds).toBeCloseTo(0.3, 6)
  })

  it('模糊区:1 个重复 ACK、150ms 补齐 → reordering/low,并附加不确定性限制说明', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 6, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 7, time: 0.2, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 8, time: 0.21, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    expect(evs).toHaveLength(1)
    const e = evs[0]
    expect(e.kind).toBe('reordering')
    expect(e.inference.confidence).toBe('low')
    expect(e.limitations.some((l) => l.includes('乱序与丢包可能表现相同'))).toBe(true)
    // 低置信度时措辞必须保守:不断言,只说"更可能"
    expect(e.inference.statement).toMatch(/更可能|无法排除/)
  })

  it('重叠填补(与已见字节重叠)→ possible-loss-or-delay/high', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      // 51–211:覆盖整个缺口 101–201,且与前段 51–101 重叠 → 同一段字节被发了两次
      c2s({ number: 6, time: 0.08, tcpFlags: PSHACK, tcpSeq: 51, tcpAck: 1, tcpLen: 160, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.09, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    // 该报文既填补缺口又重发已见字节:缺口事件之外还会有一条伪重传类事件(既有行为)
    const loss = evs.find((e) => e.kind === 'possible-loss-or-delay')
    expect(loss).toBeDefined()
    expect(loss!.inference.confidence).toBe('high')
    expect(loss!.recovered).toBe(true)
    expect(loss!.classificationSignals?.fillerCarriesOnlyNewBytes).toBe(false)
    // 重叠填补可观测到"同一段字节发了两次":观察层措辞为「重发」,
    // 且证据值填填补报文自身 seq(51),不是缺口起点(101)——点击验证要对得上
    const fillObs = loss!.observations.find((o) => o.statement.includes('重新发送'))
    expect(fillObs?.statement).toBe('缺失数据被重新发送(填补段与此前已见字节重叠)')
    expect(fillObs?.value).toBe(51)
  })

  it('观察/推断分层:全新字节的填补在观察层不得写成「被重新发送」(推断进分类,不进事实)', () => {
    const evs = run([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 6, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      s2c({ number: 7, time: 0.07, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      s2c({ number: 8, time: 0.08, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
      c2s({ number: 9, time: 0.1, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      s2c({ number: 10, time: 0.11, tcpFlags: ACK, tcpSeq: 1, tcpAck: 301, tcpLen: 0, tcpCompleteness: 15 }),
    ])
    const loss = evs.find((e) => e.kind === 'possible-loss-or-delay')!
    expect(loss.classificationSignals?.fillerCarriesOnlyNewBytes).toBe(true)
    // 填补段字节在本抓包中从未出现过:「被重新发送」不可观测,只能陈述"由后续报文补齐"
    const fillObs = loss.observations.find((o) => /补齐|重新发送/.test(o.statement))
    expect(fillObs?.statement).toBe('缺失数据由后续报文补齐(填补段携带全新字节)')
    expect(fillObs?.value).toBe(101)
    // 重传判定保留在分类/推断层(rationale 与 kind),不渗入观察陈述
    expect(loss.observations.some((o) => o.statement.includes('重新发送'))).toBe(false)
    expect(loss.rationale).toBeTruthy()
  })

  it('rationale 一律非空,且不含确定性丢包断言', () => {
    const scenarios = [
      lossChain(),
      // 相邻交换(高置信乱序)
      [
        ...handshake(),
        c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
        c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
        c2s({ number: 6, time: 0.055, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      ],
      // 模糊区(低置信乱序)
      [
        ...handshake(),
        c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
        c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
        s2c({ number: 6, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
        c2s({ number: 7, time: 0.2, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      ],
      // 无 Gap 的伪重传(M3 验收线)
      [
        ...handshake(),
        c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
        s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpCompleteness: 15 }),
        c2s({ number: 6, time: 0.3, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100, tcpCompleteness: 15 }),
      ],
    ]
    for (const packets of scenarios) {
      for (const e of run(packets)) {
        expect(e.rationale).toBeTruthy()
        expect(e.rationale!).not.toMatch(/确定丢包|一定是丢包/)
        // 已填补的缺口事件必须携带分类信号(Why 面板数据契约)
        if (e.recovered && e.gap != null) {
          expect(e.classificationSignals).toBeDefined()
        }
      }
    }
  })
})
