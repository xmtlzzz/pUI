import { describe, expect, it } from 'vitest'
import { buildReportModel, defaultReportName, REPORT_SECTIONS, type ReportModel } from './reportModel'
import type { Conversation, Packet } from '../../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP SYN-ACK' },
  { number: 3, time: 0.5, len: 300, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'HTTP GET /', tcpAnalysis: ['retransmission'] },
  { number: 4, time: 0.6, len: 300, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'HTTP GET /', tcpAnalysis: ['retransmission', 'out-of-order'] },
  { number: 5, time: 0.7, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP ACK', tcpAnalysis: ['duplicate-ack'] },
]

const conv: Conversation = {
  id: 'k', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'http', packetCount: 5, bytes: 780,
  start: 0, end: 0.7, duration: 0.7, packets,
  issues: [
    { type: 'retransmission', message: '观察到 2 次 TCP 重传(重传本身不等于丢包,需结合序列空间缺口判断)' },
    { type: 'out-of-order', message: '观察到 1 次乱序到达', packetNumber: 4 },
  ],
}

function fact(m: ReportModel, label: string): string | undefined {
  return m.summary.find((f) => f.label === label)?.value
}

describe('buildReportModel — 会话分析报告模型', () => {
  it('概要事实齐全:两端(剥端口)/协议/包数/总字节/时间范围与跨度(3 位小数)', () => {
    const m = buildReportModel(conv)
    expect(m.title).toBe('会话分析报告')
    expect(fact(m, '客户端')).toBe('1.1.1.1')
    expect(fact(m, '服务端')).toBe('2.2.2.2')
    expect(fact(m, '协议')).toBe('http')
    expect(fact(m, '包数')).toBe('5')
    expect(fact(m, '总字节')).toBe('780B')
    expect(fact(m, '时间范围')).toBe('0.000~0.700s')
    expect(fact(m, '时间跨度')).toBe('0.700s')
  })

  it('TCP 分析标记统计:按标记计数并附首个样本包号(按首次出现排序)', () => {
    const m = buildReportModel(conv)
    expect(m.findings.stats).toEqual([
      { flag: 'retransmission', count: 2, firstPacket: 3 },
      { flag: 'out-of-order', count: 1, firstPacket: 4 },
      { flag: 'duplicate-ack', count: 1, firstPacket: 5 },
    ])
  })

  it('issues 逐条入模(类型/说明/关联包号),未关联包号为 null', () => {
    const m = buildReportModel(conv)
    expect(m.findings.issues).toEqual([
      { type: 'retransmission', message: '观察到 2 次 TCP 重传(重传本身不等于丢包,需结合序列空间缺口判断)', packetNumber: null },
      { type: 'out-of-order', message: '观察到 1 次乱序到达', packetNumber: 4 },
    ])
    expect(m.findings.note).toBeNull()
  })

  it('无异常时明确写「未检出异常」:note 命中、issues/stats 为空', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const m = buildReportModel(clean)
    expect(m.findings.note).toContain('未检出异常')
    expect(m.findings.issues).toEqual([])
    expect(m.findings.stats).toEqual([])
  })

  it('generatedAt 缺省为 null(渲染时省略该行);传入时原样承载', () => {
    expect(buildReportModel(conv).generatedAt).toBeNull()
    expect(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }).generatedAt).toBe('2026-08-29 10:00:00')
  })

  it('时序表复用 transcriptTableLines:默认完整逐行,行数 = 报文数', () => {
    const m = buildReportModel(conv)
    expect(m.timeline.modeLabel).toContain('完整逐行')
    expect(m.timeline.emptyText).toBeNull()
    expect(m.timeline.tableLines).toHaveLength(2 + packets.length) // 表头 + 分隔行 + 5 报文
    expect(m.timeline.tableLines[0]).toBe('| # | 时间(s) | 方向 | 协议 | 概要 | 长度 |')
  })

  it('compact=true 透传:连续相同报文合并为区间行,模式标注为紧凑区间', () => {
    const repeated: Packet[] = [
      { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 2, time: 0.01, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 3, time: 0.02, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 4, time: 0.03, len: 1400, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP PSH-ACK', tcpAnalysis: ['retransmission'] },
    ]
    const conv2: Conversation = { id: 'k2', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'tcp', packetCount: 4, bytes: 1580, start: 0, end: 0.03, duration: 0.03, packets: repeated, issues: [] }
    const m = buildReportModel(conv2, { compact: true })
    expect(m.timeline.modeLabel).toContain('紧凑区间')
    expect(m.timeline.tableLines.join('\n')).toContain('| #1\u2013#3 | 3 |')
    // 紧凑行数显著少于逐行
    const full = buildReportModel(conv2).timeline.tableLines
    expect(m.timeline.tableLines.length).toBeLessThan(full.length)
  })

  it('anomalies=true 透传:仅保留带分析标记的报文行,模式标注为仅异常包', () => {
    const m = buildReportModel(conv, { anomalies: true })
    expect(m.timeline.modeLabel).toContain('仅异常包')
    const rows = m.timeline.tableLines.filter((l) => /^\| \d/.test(l))
    expect(rows).toHaveLength(3) // 仅 #3/#4/#5 带分析标记
    expect(m.timeline.tableLines.some((l) => /^\| 1 \|/.test(l))).toBe(false)
    expect(m.timeline.tableLines.some((l) => /^\| 2 \|/.test(l))).toBe(false)
    expect(m.timeline.tableLines.some((l) => /^\| 3 \|/.test(l))).toBe(true)
  })

  it('anomalies 且无标记报文:时序表为空,附空态文案', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const m = buildReportModel(clean, { anomalies: true })
    expect(m.timeline.tableLines).toHaveLength(0)
    expect(m.timeline.emptyText).toContain('未检出 TCP 分析标记')
  })

  it('章节标题为标准报告的渐进层级(一~四 + 二级小节),文案中文', () => {
    expect(REPORT_SECTIONS.summary).toContain('报告概要')
    expect(REPORT_SECTIONS.findings).toContain('异常与发现')
    expect(REPORT_SECTIONS.timeline).toContain('会话时序')
    expect(REPORT_SECTIONS.methodology).toContain('证据口径与限制')
    expect(REPORT_SECTIONS.issues).toContain('会话异常')
    expect(REPORT_SECTIONS.stats).toContain('TCP 分析标记统计')
  })

  it('证据口径与限制为固定说明(观察/推断分层、单观察点、正常参考不进入报告)', () => {
    const m = buildReportModel(conv)
    const all = m.methodology.join('\n')
    expect(all).toContain('观察')
    expect(all).toContain('推断')
    expect(all).toContain('单观察点')
    expect(all).toContain('正常参考')
    // 固定口径:同输入不变(与确定性测试互证)
    expect(m.methodology).toEqual(buildReportModel(conv).methodology)
  })

  it('确定性:同输入两次构建,模型逐字一致(无 Date.now 等易变注入)', () => {
    expect(JSON.stringify(buildReportModel(conv, { generatedAt: 't' }))).toBe(
      JSON.stringify(buildReportModel(conv, { generatedAt: 't' })),
    )
  })
})

describe('defaultReportName — ASCII 安全导出名', () => {
  it('风格对齐 defaultCompareReportName:report_<safe>.<ext>', () => {
    expect(defaultReportName(conv, 'md')).toBe('report_1.1.1.1_2.2.2.2.md')
    expect(defaultReportName(conv, 'docx')).toBe('report_1.1.1.1_2.2.2.2.docx')
    expect(defaultReportName(conv, 'pdf')).toBe('report_1.1.1.1_2.2.2.2.pdf')
  })

  it('中文字符与尖括号被清洗,清洗后为空时回退占位名', () => {
    const cjk: Conversation = { ...conv, client: '中文<主机>:1', server: 'a.b:2' }
    const name = defaultReportName(cjk, 'md')
    expect(name).toMatch(/^report_[\w.-]+\.md$/)
    expect(name).not.toMatch(/[\u4e00-\u9fff<>]/)
    const empty: Conversation = { ...conv, client: '::', server: '::' }
    expect(defaultReportName(empty, 'docx')).toBe('report_session.docx')
  })
})
