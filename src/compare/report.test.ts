import { beforeEach, describe, expect, it } from 'vitest'
import { buildCompareReport, defaultCompareFileName } from './report'
import { renderCompareReportHtml, renderCompareReportMd } from './render'
import type { CompareReportInput, CompareReportModel } from './report'
import type { AlignedPair, AlignmentResult, UnmatchedSide } from './align'
import type { Conversation, Packet } from '../model/types'
import type { ConversationDiff, EventDiffEntry, PacketDiffStats, TimelineRow } from './diff'
import type { VerdictEntry } from './verdict'

// ---- fixture:手工构造(不依赖 tshark) ----

function pkt(n: number, t: number, fromA: boolean, info: string): Packet {
  return {
    number: n,
    time: t,
    timeEpoch: 1700000000 + t,
    len: 100,
    transport: 'tcp',
    proto: 'tcp',
    srcIp: fromA ? '10.0.0.1' : '10.0.0.2',
    dstIp: fromA ? '10.0.0.2' : '10.0.0.1',
    srcPort: fromA ? 1000 : 80,
    dstPort: fromA ? 80 : 1000,
    info,
    direction: fromA ? 'request' : 'response',
  }
}

function mkConv(id: string, packets: Packet[]): Conversation {
  const start = packets[0]?.time ?? 0
  const end = packets[packets.length - 1]?.time ?? 0
  return {
    id,
    client: '10.0.0.1:1000',
    server: '10.0.0.2:80',
    protocol: 'http',
    packetCount: packets.length,
    bytes: packets.length * 100,
    start,
    end,
    duration: end - start,
    packets,
    issues: [],
  }
}

const convA = mkConv('a1', [pkt(1, 0.0, true, 'GET /'), pkt(2, 0.1, false, '200 OK')])
const convB = mkConv('b1', [pkt(1, 0.001, false, '200 OK(b)')])

const stats: PacketDiffStats = { countA: 2, countB: 1, bytesA: 200, bytesB: 100 }
const eventDiffs: EventDiffEntry[] = [
  { kind: 'possible-loss-or-delay', gapText: '100–200', recovered: false, onlyIn: 'A' },
]
const timeline: TimelineRow[] = [
  { timeEpoch: 1700000000.0, side: 'A', numberA: 1, infoA: 'GET /' },
  { timeEpoch: 1700000000.001, side: 'AB', numberA: 2, numberB: 1, infoA: '200 OK', infoB: '200 OK(b)' },
]
const diffModel: ConversationDiff = { stats, eventDiffs, timeline, truncated: false }

const pairs: AlignedPair[] = [{ sideA: convA, sideB: convB }]
const unmatched: UnmatchedSide[] = [{ side: 'A', conv: mkConv('a2', [pkt(9, 5.0, true, 'orphan')]) }]
const alignment: AlignmentResult = { pairs, unmatched }
const verdicts: VerdictEntry[] = [
  { statement: 'warn-line', severity: 'warn' },
  { statement: 'info-line', severity: 'info' },
]

function input(): CompareReportInput {
  return {
    fileA: 'a.pcapng',
    fileB: 'b.pcapng',
    alignment,
    diffs: new Map([['a1', diffModel]]),
    verdicts: new Map([['a1', verdicts]]),
  }
}

describe('defaultCompareFileName', () => {
  it('sanitizes label to filesystem-safe name with ext', () => {
    // 非 ASCII 与危险字符压成下划线,首尾下划线 trim(与 defaultEvidenceHtmlName 同规则)
    expect(defaultCompareFileName('对照 A/B 报告', 'md')).toBe('compare_A_B.md')
  })

  it('falls back to "report" for empty/unsafe label', () => {
    expect(defaultCompareFileName('', 'html')).toBe('compare_report.html')
    expect(defaultCompareFileName('///', 'html')).toBe('compare_report.html')
    // 全部字符被压缩成下划线后 trim 为空 → 同样回退
    expect(defaultCompareFileName('对照 测试/报告', 'md')).toBe('compare_report.md')
  })
})

describe('buildCompareReport', () => {
  it('produces a deterministic model: two calls identical', () => {
    const m1 = buildCompareReport(input())
    const m2 = buildCompareReport(input())
    expect(JSON.stringify(m1)).toBe(JSON.stringify(m2))
  })

  it('carries summary, per-pair sections, unmatched rows and methodology', () => {
    const m = buildCompareReport(input())
    // 概要:文件名 + 对齐统计
    expect(m.summary).toEqual([
      { label: 'A 侧文件', value: 'a.pcapng' },
      { label: 'B 侧文件', value: 'b.pcapng' },
      { label: '对齐会话对', value: '1' },
      { label: '未匹配会话', value: '1(A 侧 1 / B 侧 0)' },
    ])
    // 逐对会话:端点 + stats + 事件 + 结论 + 时间线
    expect(m.pairs).toHaveLength(1)
    const p = m.pairs[0]
    expect(p.endpointLabel).toBe('10.0.0.1:1000 ↔ 10.0.0.2:80')
    expect(p.statsRow).toEqual({ label: 'a1 ↔ b1', stats })
    expect(p.eventRows).toEqual(eventDiffs.map((e) => ({ ...e, gapText: e.gapText ?? '' })))
    expect(p.verdicts).toEqual(verdicts)
    expect(p.timelineRows).toEqual(timeline)
    expect(p.timelineTruncated).toBe(false)
    // 未匹配会话行(包数降序由对齐层保证)
    expect(m.unmatchedRows).toEqual([{ side: 'A', label: '10.0.0.1:1000 → 10.0.0.2:80', packetCount: 1 }])
    // 口径固定文字(观察层红线)
    expect(m.methodology.some((l) => l.includes('不构成对丢包位置或设备行为的断言'))).toBe(true)
  })

  it('marks timeline truncation from diff model', () => {
    const inp = input()
    inp.diffs = new Map([['a1', { ...diffModel, truncated: true }]])
    expect(buildCompareReport(inp).pairs[0].timelineTruncated).toBe(true)
  })
})

describe('renderCompareReportMd', () => {
  it('is deterministic and contains all sections', () => {
    const md1 = renderCompareReportMd(buildCompareReport(input()))
    const md2 = renderCompareReportMd(buildCompareReport(input()))
    expect(md1).toBe(md2)
    expect(md1).toContain('# 双观测点对照分析报告')
    expect(md1).toContain('a.pcapng')
    expect(md1).toContain('| A 侧文件 | a.pcapng |')
    expect(md1).toContain('10.0.0.1:1000 ↔ 10.0.0.2:80')
    expect(md1).toContain('| 包数 | 2 | 1 |')
    expect(md1).toContain('| 字节 | 200 | 100 |')
    expect(md1).toContain('| possible-loss-or-delay | 100–200 | 未恢复 | 仅 A |')
    expect(md1).toContain('| warn | warn-line |')
    expect(md1).toContain('| 仅 A 见到 | #1 | GET / | — | — |')
    expect(md1).toContain('| 两侧均见 | #2 | 200 OK | #1 | 200 OK(b) |')
    expect(md1).toContain('未匹配会话')
    expect(md1).toContain('口径与限制')
  })

  it('escapes pipe characters in cell text to keep table structure', () => {
    const inp = input()
    inp.verdicts = new Map([['a1', [{ statement: 'a|b', severity: 'info' }]]])
    const md = renderCompareReportMd(buildCompareReport(inp))
    expect(md).toContain('a\\|b')
  })

  describe('Markdown 注入防护(存储型 XSS)', () => {
    /** 构造一个把抓包可控自由文本塞满各渲染位置(时间线信息/端点标签/邮箱标签/文件名/结论)的模型 */
    const payload = '<img src=x onerror=alert(1)>'
    const scripty = '<script>evil()</script>'
    let inp: CompareReportInput
    beforeEach(() => {
      inp = input()
      inp.fileA = scripty + '.pcap'
      inp.diffs = new Map([
        [
          'a1',
          {
            ...diffModel,
            stats,
            timeline: [
              { timeEpoch: 1, side: 'A', numberA: 1, infoA: payload },
              { timeEpoch: 2, side: 'B', numberB: 7, infoB: payload },
            ],
          },
        ],
      ])
      inp.verdicts = new Map([['a1', [{ statement: payload, severity: 'warn' }]]])
    })

    it('时间线信息(infoA/infoB)中的尖括号被剥除:导出 MD 不存在原始 <img>/<script> 标签', () => {
      const md = renderCompareReportMd(buildCompareReport(inp))
      // 全库其它渲染器口径:尖括号整体剥除(防 <img onerror> 透传 Typora/Obsidian/marked 系)
      expect(md).not.toContain('<img')
      expect(md).not.toContain('<script')
      expect(md).not.toContain(payload)
    })

    it('结论/概要等单元格中的尖括号同样剥除,& 实体转义为 &amp;', () => {
      const model2: CompareReportModel = buildCompareReport(inp)
      model2.summary = [...model2.summary, { label: '可疑值', value: 'a&b<img src=x onerror=alert(1)>' }]
      const md = renderCompareReportMd(model2)
      expect(md).not.toContain('<img')
      expect(md).toContain('a&amp;b')
    })

    it('端点标签 endpointLabel/statsRow.label/unmatchedRow.label 不携带原始尖括号', () => {
      const m = buildCompareReport(inp)
      // 对齐层 endpointLabel 来自 client/server 主机名 —— 抓包可控,作为防御性验证
      const model2: CompareReportModel = {
        ...m,
        pairs: m.pairs.map((p) => ({ ...p, endpointLabel: '<img src=x onerror=alert(2)>', statsRow: { ...p.statsRow, label: '<b>l</b>' } })),
        unmatchedRows: [{ ...m.unmatchedRows[0], label: '<script>evil()</script>' }],
      }
      const md = renderCompareReportMd(model2)
      expect(md).not.toContain('<img')
      expect(md).not.toContain('<script>')
      expect(md).not.toContain('<b>')
    })

    it('MD 与 HTML 渲染器输出均不泄露指纹标签之外的原始尖括号', () => {
      const m = buildCompareReport(inp)
      const md = renderCompareReportMd(m)
      const html = renderCompareReportHtml(buildCompareReport(inp))
      const rawAngles = (s: string) => (s.match(/<[^>]*>/g) ?? []).filter((t) => /<(\/?)(img|script|b)>/i.test(t)).length
      expect(rawAngles(md)).toBe(0)
      expect(rawAngles(html)).toBe(0)
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
      expect(md).not.toContain(payload)
    })
  })
})

describe('renderCompareReportHtml', () => {
  it('is a full offline document with inline CSS, no remote resources', () => {
    const html = renderCompareReportHtml(buildCompareReport(input()))
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('<style>')
    expect(html).not.toMatch(/<script/i)
    expect(html).not.toMatch(/https?:\/\//)
    expect(html).toContain('<title>双观测点对照分析报告</title>')
  })

  it('is deterministic: two renders identical', () => {
    expect(renderCompareReportHtml(buildCompareReport(input()))).toBe(renderCompareReportHtml(buildCompareReport(input())))
  })

  it('escapes injection payloads: img/script count is zero after escaping', () => {
    const inp = input()
    inp.diffs = new Map([
      [
        'a1',
        {
          ...diffModel,
          timeline: [{ timeEpoch: 1, side: 'A', numberA: 1, infoA: '<img src=x onerror=alert(1)>' }],
        },
      ],
    ])
    inp.fileA = '<script>evil()</script>.pcap'
    const html = renderCompareReportHtml(buildCompareReport(inp))
    // 全实体转义后文档中不出现可执行 img/script 标签
    expect((html.match(/<img/g) ?? []).length).toBe(0)
    expect((html.match(/<script/gi) ?? []).length).toBe(0)
    // 载荷以转义形态可见
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('renders truncation marker when timeline was truncated', () => {
    const inp = input()
    inp.diffs = new Map([['a1', { ...diffModel, truncated: true }]])
    const md = renderCompareReportMd(buildCompareReport(inp))
    expect(md).toContain('已截断')
    const html = renderCompareReportHtml(buildCompareReport(inp))
    expect(html).toContain('已截断')
  })
})
