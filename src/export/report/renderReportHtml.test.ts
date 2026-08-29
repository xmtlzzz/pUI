// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { buildReportModel } from './reportModel'
import { renderReportHtml } from './renderReportHtml'
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

function doc(html: string): Document {
  return new DOMParser().parseFromString(html, 'text/html')
}

describe('renderReportHtml — 会话分析报告 HTML(打印为 PDF)渲染', () => {
  it('完整独立文档:doctype 开头、lang=zh-CN、内联 style、title', () => {
    const html = renderReportHtml(buildReportModel(conv))
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('lang="zh-CN"')
    expect(html).toContain('<style>')
    const d = doc(html)
    expect(d.querySelector('title')?.textContent).toBe('会话分析报告')
    expect(d.querySelector('style')?.textContent).toContain('@page')
  })

  it('标题层级渐进:h1 唯一,四个章节为 h2 且顺序正确;小节为 h3', () => {
    const d = doc(renderReportHtml(buildReportModel(conv)))
    expect(d.querySelectorAll('h1')).toHaveLength(1)
    expect(d.querySelector('h1')?.textContent).toBe('会话分析报告')
    const h2s = [...d.querySelectorAll('h2')].map((h) => h.textContent ?? '')
    expect(h2s).toEqual(['一、报告概要', '二、异常与发现', '三、会话时序', '四、证据口径与限制'])
    const h3s = [...d.querySelectorAll('h3')].map((h) => h.textContent ?? '')
    expect(h3s).toEqual(['会话异常', 'TCP 分析标记统计'])
  })

  it('概要表格承载两端/协议/包数/字节/时间范围/跨度;生成时间可选', () => {
    const d = doc(renderReportHtml(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' })))
    const text = d.body.textContent ?? ''
    for (const s of ['1.1.1.1', '2.2.2.2', 'http', '5', '780B', '0.000~0.700s', '0.700s', '生成时间: 2026-08-29 10:00:00']) {
      expect(text).toContain(s)
    }
    const without = doc(renderReportHtml(buildReportModel(conv)))
    expect(without.body.textContent ?? '').not.toContain('生成时间')
  })

  it('时序表:thead 表头 6 列 + 每包一行;thead/tr 打印防断行样式齐备', () => {
    const html = renderReportHtml(buildReportModel(conv))
    const d = doc(html)
    const tables = d.querySelectorAll('table')
    const timeline = tables[tables.length - 1] // 时序表在文档最后
    expect(timeline.querySelectorAll('thead th')).toHaveLength(6)
    expect(timeline.querySelectorAll('tbody tr')).toHaveLength(5)
    const firstRow = timeline.querySelectorAll('tbody tr')[0]
    expect(firstRow.querySelectorAll('td')[0].textContent).toBe('1')
    expect(firstRow.querySelectorAll('td')[4].textContent).toBe('TCP SYN')
    const css = d.querySelector('style')?.textContent ?? ''
    expect(css).toContain('thead') // display: table-header-group(跨页重复表头)
    expect(css).toContain('break-inside') // tr 防分页断行
    expect(d.body.textContent ?? '').toContain('当前模式:')
  })

  it('紧凑/仅异常模式透传:合并区间与过滤行数', () => {
    const repeated: Packet[] = [
      { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 2, time: 0.01, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 3, time: 0.02, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
      { number: 4, time: 0.03, len: 1400, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP PSH-ACK', tcpAnalysis: ['retransmission'] },
    ]
    const conv2: Conversation = { id: 'k2', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'tcp', packetCount: 4, bytes: 1580, start: 0, end: 0.03, duration: 0.03, packets: repeated, issues: [] }
    const compact = doc(renderReportHtml(buildReportModel(conv2, { compact: true })))
    const compactText = compact.body.textContent ?? ''
    expect(compactText).toContain('紧凑区间')
    expect(compactText).toContain('#1–#3') // 连续相同 3 行合并为区间
    const compactTable = compact.querySelectorAll('table')[compact.querySelectorAll('table').length - 1]
    expect(compactTable.querySelectorAll('tbody tr')).toHaveLength(2) // 区间组 + 重传行

    const anomalies = doc(renderReportHtml(buildReportModel(conv, { anomalies: true })))
    expect(anomalies.body.textContent ?? '').toContain('仅异常包')
    const timeline = anomalies.querySelectorAll('table')[anomalies.querySelectorAll('table').length - 1]
    expect(timeline.querySelectorAll('tbody tr')).toHaveLength(3) // 仅 #3/#4/#5 带标记
  })

  it('XSS 防护:抓包内容转义,文档内不产生注入元素', () => {
    const evil: Packet[] = [
      { number: 9, time: 1, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request',
        info: 'HTTP GET /a|b<img src=x onerror=alert(1)>`q`' },
    ]
    const evilConv: Conversation = {
      ...conv, packets: evil, packetCount: 1, bytes: 60, end: 1, duration: 1,
      issues: [{ type: 'one-way', message: '可疑 `说明` & "引用" <b>加粗</b>' }],
    }
    const html = renderReportHtml(buildReportModel(evilConv))
    const d = doc(html)
    // 无注入元素:img/b/script 均不得作为 DOM 元素出现
    expect(d.querySelector('img')).toBeNull()
    expect(d.querySelector('b')).toBeNull()
    expect(d.querySelector('script')).toBeNull()
    // 文本保留(尖括号已被 mdCell 展示层剥除),引号与 & 被实体转义
    expect(d.body.textContent ?? '').toContain('onerror=alert(1)')
    expect(html).toContain('&quot;')
    expect(html).toContain('&amp;')
    expect(html).not.toContain('<img')
  })

  it('无异常时明确写「未检出异常」,不渲染空小节', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const d = doc(renderReportHtml(buildReportModel(clean)))
    expect(d.body.textContent ?? '').toContain('未检出异常')
    expect([...d.querySelectorAll('h3')].map((h) => h.textContent)).toEqual([])
  })

  it('时序表为空(仅异常模式无标记)时输出空态文案而非空表', () => {
    const clean: Conversation = { ...conv, issues: [], packets: packets.slice(0, 2), packetCount: 2, bytes: 120, end: 0.03, duration: 0.03 }
    const d = doc(renderReportHtml(buildReportModel(clean, { anomalies: true })))
    expect(d.body.textContent ?? '').toContain('未检出 TCP 分析标记')
    expect(d.querySelectorAll('table')).toHaveLength(1) // 仅剩概要表
  })

  it('证据口径与限制逐条列出', () => {
    const d = doc(renderReportHtml(buildReportModel(conv)))
    const items = [...d.querySelectorAll('ul li')].map((li) => li.textContent ?? '')
    expect(items.length).toBeGreaterThan(0)
    expect(items.join('\n')).toContain('单观察点')
    expect(items.join('\n')).toContain('正常参考')
  })

  it('确定性:同输入两次渲染逐字一致', () => {
    const a = renderReportHtml(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))
    const b = renderReportHtml(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))
    expect(a).toBe(b)
  })
})
