import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { CAPTURE_FIELDS } from '../../parse/captureFields'
import { parsePackets } from '../../parse/parsePackets'
import { analyzeStream } from './streamAnalysis'
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
  return analyzeStream(parsePackets(json))
}

describe.skipIf(!hasTshark)('真实 tshark 场景 → 序列空间分析', () => {
  const caps = buildScenarioCaptures()

  it('正常连续传输:无 Gap,握手完整', () => {
    const a = analyze('normal', caps.normal)
    expect(a.midStream).toBe(false)
    expect(a.gaps).toEqual([])
    expect(a.segments.every((s) => s.classification !== 'new-ahead-of-gap')).toBe(true)
  })

  it('Gap + 三次 Dup ACK + SACK + 重传 + 恢复:Gap 被正确还原并填补', () => {
    const a = analyze('gap-sack', caps.gapSack)
    expect(a.gaps).toHaveLength(1)
    const g = a.gaps[0]
    expect([g.start, g.end, g.byteCount]).toEqual([101, 201, 100])
    expect(g.filled).toBe(true)
    expect(g.sackCovered).toBe(true) // SACK 报告缺口之后的数据已到达
    // 填补者就是那个重传报文
    expect(a.segments.find((s) => s.packetNumber === g.filledByPacket)?.classification).toBe('out-of-order-fill')
  })

  it('乱序后补齐:tshark 标注为 retransmission,但序列空间证明只是乱序到达', () => {
    // 这是本项目的核心论点:标签只是现象,不能当结论。
    // 实测 tshark 给该帧打 tcp.analysis.retransmission,而它其实是迟到的原始段。
    const a = analyze('out-of-order', caps.outOfOrder)
    const filler = a.segments.find((s) => s.classification === 'out-of-order-fill')
    expect(filler).toBeDefined()
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].filled).toBe(true)
    // 该段承载的是此前从未见过的字节 → 不是"重发已发过的数据"
    expect(filler!.newBytes).toBe(filler!.seqLen)
  })

  it('伪重传:数据已确认后重发,序列空间中没有任何 Gap', () => {
    // M3 验收线:无 meaningful gap 的重传不得被归为确定性数据丢失
    const a = analyze('spurious', caps.spurious)
    expect(a.gaps).toEqual([])
    const dup = a.segments.find((s) => s.classification === 'pure-duplicate')
    expect(dup).toBeDefined()
    expect(dup!.newBytes).toBe(0) // 没带来任何新字节
  })

  it('中途抓包:识别为 mid-stream,且不从流起点造出幻影 Gap', () => {
    // 起始序列号 500001,若把"没见过 0..500001"当缺失,会造出 50 万字节的假 Gap;
    // 另外此处 SACK 的原始值(500201)必须与 seq_raw 同空间,否则同样造假 Gap
    const a = analyze('mid-stream', caps.midStream)
    expect(a.midStream).toBe(true)
    expect(a.gaps).toHaveLength(1)
    expect([a.gaps[0].start, a.gaps[0].byteCount]).toEqual([500101, 100])
  })
})
