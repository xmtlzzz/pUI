import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { CAPTURE_FIELDS } from '../../parse/captureFields'
import { parsePackets } from '../../parse/parsePackets'
import { analyzeStream } from './streamAnalysis'
import { detectTcpEvents } from './events'
import { buildScenarioCaptures } from './fixtures/scenarios'

/**
 * 真实 tshark 端到端:合成 pcapng → tshark(与生产同参)→ parsePackets → analyzeStream。
 *
 * 这层测试的价值在于覆盖「单测 mock 不到」的真实字段形态:SACK 并行数组、
 * 相对/原始序号、tcp.completeness 位掩码。无 tshark 的环境自动跳过,不阻塞 CI。
 */
const TSHARK =
  process.env.TSHARK ?? (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\tshark.exe' : 'tshark')
const hasTshark = (() => {
  try {
    execFileSync(TSHARK, ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

const OUT = join(__dirname, '..', '..', '..', 'node_modules', '.cache', 'pui-scenarios')

function analyze(name: string, bytes: Buffer) {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true })
  const pcap = join(OUT, `${name}.pcapng`)
  writeFileSync(pcap, bytes)
  const args = [
    // 与 Rust run_capture 完全一致:关闭相对序号,使 seq/ack/SACK 同处 raw 空间
    '-o',
    'tcp.relative_sequence_numbers:FALSE',
    '-r',
    pcap,
    '-T',
    'json',
    ...CAPTURE_FIELDS.flatMap((f) => ['-e', f]),
  ]
  const json = execFileSync(TSHARK, args, { maxBuffer: 64 * 1024 * 1024 }).toString()
  const packets = parsePackets(json)
  const facts = analyzeStream(packets)
  return { packets, facts, events: detectTcpEvents(facts, packets) }
}

describe.skipIf(!hasTshark)('真实 tshark 场景 → 序列空间分析', () => {
  const caps = buildScenarioCaptures()

  it('正常连续传输:无 Gap,握手完整,不产生任何事件', () => {
    const { facts, events } = analyze('normal', caps.normal)
    expect(facts.midStream).toBe(false)
    expect(facts.gaps).toEqual([])
    expect(facts.segments.every((s) => s.classification !== 'new-ahead-of-gap')).toBe(true)
    expect(events).toEqual([]) // 零误报
  })

  it('Gap + 三次 Dup ACK + SACK + 重传 + 恢复:Gap 被正确还原并填补', () => {
    const { facts } = analyze('gap-sack', caps.gapSack)
    expect(facts.gaps).toHaveLength(1)
    const g = facts.gaps[0]
    expect([g.start, g.end, g.byteCount]).toEqual([101, 201, 100])
    expect(g.filled).toBe(true)
    expect(g.sackCovered).toBe(true) // SACK 报告缺口之后的数据已到达
    // 填补者就是那个重传报文
    expect(facts.segments.find((s) => s.packetNumber === g.filledByPacket)?.classification).toBe('out-of-order-fill')
  })

  it('Gap 场景生成「疑似丢包/延迟」事件,证据链完整可下钻', () => {
    const { events, packets } = analyze('gap-sack', caps.gapSack)
    expect(events).toHaveLength(1)
    const e = events[0]
    expect(e.kind).toBe('possible-loss-or-delay')
    expect(e.recovered).toBe(true)
    expect(e.sackPresent).toBe(true)
    expect(e.duplicateAckCount).toBe(3) // 三个 dup ACK 报文,不因字段多值而翻倍
    expect(e.retransmissionPacket).toBeDefined()
    expect(e.recoveryAckPacket).toBeDefined()
    // 每条证据都指向真实存在的报文
    const nums = new Set(packets.map((p) => p.number))
    for (const r of e.inference.evidenceRefs) expect(nums.has(r.packetNumber)).toBe(true)
  })

  it('乱序后补齐:tshark 标注为 retransmission,但序列空间证明只是乱序到达', () => {
    // 这是本项目的核心论点:标签只是现象,不能当结论。
    // 实测 tshark 给该帧打 tcp.analysis.retransmission,而它其实是迟到的原始段。
    const { facts, packets } = analyze('out-of-order', caps.outOfOrder)
    const filler = facts.segments.find((s) => s.classification === 'out-of-order-fill')
    expect(filler).toBeDefined()
    expect(facts.gaps).toHaveLength(1)
    expect(facts.gaps[0].filled).toBe(true)
    // 该段承载的是此前从未见过的字节 → 不是"重发已发过的数据"
    expect(filler!.newBytes).toBe(filler!.seqLen)
    // 前提确认:tshark 确实打了误导性标签(否则这个用例就失去意义)
    expect(packets.find((p) => p.number === filler!.packetNumber)?.tcpAnalysis).toContain('retransmission')
  })

  it('乱序场景被归为 reordering,而非丢包(标签不参与分类)', () => {
    const { events } = analyze('out-of-order', caps.outOfOrder)
    expect(events).toHaveLength(1)
    expect(events[0].kind).toBe('reordering')
    expect(events[0].retransmissionPacket).toBeUndefined()
    expect(events[0].severity).toBe('low')
    // 但标签仍如实出现在观察项里
    expect(events[0].observations.map((o) => o.statement).join(' ')).toMatch(/retransmission/)
  })

  it('伪重传:数据已确认后重发,序列空间中没有任何 Gap', () => {
    // M3 验收线:无 meaningful gap 的重传不得被归为确定性数据丢失
    const { facts } = analyze('spurious', caps.spurious)
    expect(facts.gaps).toEqual([])
    const dup = facts.segments.find((s) => s.classification === 'pure-duplicate')
    expect(dup).toBeDefined()
    expect(dup!.newBytes).toBe(0) // 没带来任何新字节
  })

  it('伪重传场景归为 possible-ack-loss-or-spurious,措辞不含确定性断言', () => {
    const { events } = analyze('spurious', caps.spurious)
    expect(events.map((e) => e.kind)).toEqual(['possible-ack-loss-or-spurious'])
    expect(events[0].gap).toBeUndefined()
    expect(events[0].inference.statement).not.toMatch(/确定|一定|肯定/)
  })

  it('中途抓包:识别为 mid-stream,且不从流起点造出幻影 Gap', () => {
    // 起始序列号 500001,若把"没见过 0..500001"当缺失,会造出 50 万字节的假 Gap;
    // 另外此处 SACK 的原始值(500201)必须与 seq_raw 同空间,否则同样造假 Gap
    const { facts } = analyze('mid-stream', caps.midStream)
    expect(facts.midStream).toBe(true)
    expect(facts.gaps).toHaveLength(1)
    expect([facts.gaps[0].start, facts.gaps[0].byteCount]).toEqual([500101, 100])
  })

  it('中途抓包的事件置信度下调并带抓包限制', () => {
    const { events } = analyze('mid-stream', caps.midStream)
    expect(events).toHaveLength(1)
    expect(events[0].inference.confidence).toBe('low')
    expect(events[0].limitations.some((l) => /中途/.test(l))).toBe(true)
  })
})
