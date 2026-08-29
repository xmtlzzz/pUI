import { describe, expect, it } from 'vitest'
import { buildReportModel } from './reportModel'
import { renderReportMd } from './renderReportMd'
import { transcriptTableLines } from '../exportTranscript'
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
  issues: [{ type: 'retransmission', message: '观察到 2 次 TCP 重传', packetNumber: 3 }],
}

describe('renderReportMd — 会话分析报告 Markdown 渲染', () => {
  it('标题为一级,四个章节为二级且顺序渐进(一~四)', () => {
    const md = renderReportMd(buildReportModel(conv))
    expect(md.startsWith('# 会话分析报告')).toBe(true)
    const idx = ['一、报告概要', '二、异常与发现', '三、会话时序', '四、证据口径与限制'].map((s) => md.indexOf('## ' + s))
    expect(idx.every((i) => i >= 0)).toBe(true)
    expect([...idx].sort((a, b) => a - b)).toEqual(idx) // 原序即升序 → 章节按一~四排列
    // 层级不跳档:除标题行外,一级只出现一次,二级恰 4 个章节
    expect(md.split('\n').filter((l) => /^# /.test(l))).toHaveLength(1)
    expect(md.split('\n').filter((l) => /^## /.test(l))).toHaveLength(4)
  })

  it('概要含两端/协议/包数/字节/时间范围/跨度;generatedAt 存在时加生成时间行', () => {
    const md = renderReportMd(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))
    expect(md).toContain('生成时间: 2026-08-29 10:00:00')
    expect(md).toContain('`客户端`')
    expect(md).toContain('`1.1.1.1`')
    expect(md).toContain('`http`')
    expect(md).toContain('`780B`')
    expect(md).toContain('`0.000~0.700s`')
    expect(md).toContain('时间跨度')
    expect(md).not.toMatch(/Date|生成于/) // 无易变内容混入
  })

  it('generatedAt 缺省时省略生成时间行', () => {
    const md = renderReportMd(buildReportModel(conv))
    expect(md).not.toContain('生成时间')
  })

  it('异常逐条列出(类型/说明/关联包号),TCP 分析标记统计带首个样本包号', () => {
    const md = renderReportMd(buildReportModel(conv))
    expect(md).toContain('### 会话异常')
    expect(md).toContain('| retransmission |')
    expect(md).toContain('| #3 |')
    expect(md).toContain('### TCP 分析标记统计')
    expect(md).toContain('`retransmission` | 2 | #3') // retransmission ×2,首个样本 #3
    expect(md).toContain('`out-of-order` | 1 | #4')
    expect(md).toContain('`duplicate-ack` | 1 | #5')
    expect(md).not.toContain('未检出异常')
  })

  it('无异常时明确写「未检出异常」,不渲染空小节', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const md = renderReportMd(buildReportModel(clean))
    expect(md).toContain('未检出异常')
    expect(md).not.toContain('### 会话异常')
    expect(md).not.toContain('### TCP 分析标记统计')
  })

  it('会话时序章节逐字复用 transcriptTableLines,并注明当前模式', () => {
    const m = buildReportModel(conv)
    const md = renderReportMd(m)
    expect(md).toContain('当前模式:')
    expect(md).toContain('完整逐行')
    expect(md).toContain(transcriptTableLines(conv, null, 'full').join('\n'))
  })

  it('时序模式随 compact/anomalies 选项标注', () => {
    expect(renderReportMd(buildReportModel(conv, { compact: true }))).toContain('紧凑区间')
    expect(renderReportMd(buildReportModel(conv, { anomalies: true }))).toContain('仅异常包')
  })

  it('不可信内容(mdCell 转义)不破坏表格、不注入 HTML:尖括号剥除、管道符转义', () => {
    const evil: Packet[] = [
      { number: 9, time: 1, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request',
        info: 'HTTP GET /a|b<img src=x onerror=alert(1)>`q`\nsecond line' },
    ]
    const evilConv: Conversation = {
      ...conv, packets: evil, packetCount: 1, bytes: 60, end: 1, duration: 1,
      issues: [{ type: 'one-way', message: '可疑 `说明` | <b>加粗</b>' }],
    }
    const md = renderReportMd(buildReportModel(evilConv))
    expect(md).not.toContain('<img')
    expect(md).not.toContain('<b>')
    // 注入的竖线被转义(表格行数不被拆坏)与换行被拍平
    expect(md).toContain('\\|')
    expect(md).toContain('second line')
    // 注入内容仍在单元格内(未拆出多余行):概要列整格出现
    expect(md).toContain('`HTTP GET /a\\|bimg src=x onerror=alert(1)\\`q\\` second line`')
  })

  it('时序表为空(仅异常模式无标记)时输出空态文案而非空表', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const md = renderReportMd(buildReportModel(clean, { anomalies: true }))
    expect(md).toContain('未检出 TCP 分析标记')
    expect(md).not.toContain('| 报文区间 |')
  })

  it('证据口径与限制逐条列出', () => {
    const md = renderReportMd(buildReportModel(conv))
    const section = md.split('## 四、证据口径与限制')[1] ?? ''
    expect(section).toContain('观察')
    expect(section).toContain('单观察点')
    expect(section).toContain('正常参考')
  })

  it('确定性:同输入两次渲染逐字一致', () => {
    const a = renderReportMd(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))
    const b = renderReportMd(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))
    expect(a).toBe(b)
  })
})
