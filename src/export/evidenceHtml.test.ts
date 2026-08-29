// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import type { CompareViewModel } from '../m4/viewModel'
import { exportCompareReport } from './exportCompareReport'
import { defaultEvidenceHtmlName, exportEvidenceHtml } from './evidenceHtml'

/** 与 exportCompareReport.test.ts 同构的最小 vm(不重复引擎路径;结构 = 生产输出)。
 *  fixture 数据里刻意不放 URL(远程资源红线测试要求输出不含 http(s)://)。 */
function makeVm(): CompareViewModel {
  return {
    card: {
      kindLabel: '疑似丢包 / 延迟到达',
      severity: 'medium',
      recovered: true,
      gapText: '101–201(100B)',
      observations: [
        { packetNumber: 6, statement: '序列空间存在缺口 101–201,由该报文越过缺口到达而暴露' },
        { packetNumber: 11, statement: '缺失数据被重新发送' },
      ],
      inference: { statement: '观察到数据未按连续序列到达,随后由重传补齐', confidence: 'medium' },
      limitations: ['单观察点抓包:无法定位丢包发生在哪个网络节点'],
    },
    seqSpace: {
      axisMin: 0,
      axisMax: 501,
      ticks: [100, 200, 300, 400, 500],
      seenRuns: [[0, 101]],
      gaps: [[101, 201]],
      sackBlocks: [[201, 501]],
      ackTrack: [],
      retxArrow: { seq: 101 },
      rangeLabels: [
        { start: 0, end: 101, text: '数据', kind: 'seen' },
        { start: 101, end: 201, text: '未收到', kind: 'gap' },
      ],
    },
    keyPackets: [
      { packetNumber: 6, time: 0.05, dir: 'c2s', label: 'PSH·ACK seq=201 len=100', stageIndex: 1, roleBadge: '缺口显露' },
      { packetNumber: 11, time: 0.25, dir: 's2c', label: 'ACK ack=101', stageIndex: 3, roleBadge: '重传回补' },
    ],
    stages: [
      { label: '正常传输', summary: '无缺口', fromPacket: 4, toPacket: 5, startTime: 0.03, endTime: 0.04, observationRefs: [], t0: 0, t1: 0.2 },
      { label: '恢复', summary: '缺口闭合', fromPacket: 12, toPacket: 12, startTime: 0.26, endTime: 0.26, observationRefs: [], t0: 0.8, t1: 1 },
    ],
    referenceSteps: [
      // 红线样本:右栏示意步骤,绝不能出现在导出里
      { index: 1, label: '数据段 1 · 100B', kind: 'data', detail: '按序列顺序连续发送' },
    ],
    marks: { gapRevealAt: 0.1, dupAckWindow: [0.2, 0.5], retxDrawAt: 0.6, recoverAt: 0.9 },
    direction: 'c2s',
    opposite: null,
    panorama: null,
    // 全量缺口(未按图形视窗裁剪)—— 证据报告按它列全,不缺报
    allGaps: [[101, 201]],
    eventPins: [],
    degraded: { unorderableInput: false, midStream: true, lengthUnavailable: false, noEvents: false },
    headline: '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium',
  }
}

const input = {
  fileName: 'VDI_202608.pcapng',
  conversationLabel: '10.0.0.1:1234 ↔ 93.184.216.34:443',
  eventNo: 2,
  eventTotal: 5,
  vm: makeVm(),
}

function doc(html: string): Document {
  return new DOMParser().parseFromString(html, 'text/html')
}

/** Markdown 某章节下的表格数据行数(表头 `| # |` 与分隔行 `|---|` 不计入) */
function mdRowCount(md: string, heading: string, nextHeading: string): number {
  const section = md.split(heading)[1] ?? ''
  const body = section.split(nextHeading)[0] ?? ''
  return body.split('\n').filter((l) => /^\| \d+ \|/.test(l)).length
}

/** 序列空间摘要表(seqspace)中「缺口」一行的值单元格文本(事件卡的 gapText 行不在此表) */
function htmlGapValue(d: Document): string | undefined {
  const row = [...d.querySelectorAll('table.seqspace tbody tr')].find(
    (tr) => tr.querySelectorAll('td')[0]?.textContent === '缺口',
  )
  return row?.querySelectorAll('td')[1]?.textContent ?? undefined
}

describe('exportEvidenceHtml — 事件级单文件离线 HTML 证据报告', () => {
  it('单文件离线文档:doctype 开头、lang=zh-CN、charset、内联 style、title 与打印规则齐备', () => {
    const html = exportEvidenceHtml(input)
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('lang="zh-CN"')
    expect(html).toContain('<meta charset="utf-8">')
    expect(html).toContain('<title>故障分析报告 · 事件 2/5</title>')
    const d = doc(html)
    const css = d.querySelector('style')?.textContent ?? ''
    expect(css).toContain('@page') // A4 边距
    expect(css).toContain('table-header-group') // 表格 thead 跨页重复
    expect(css).toContain('break-inside') // 行防断页
    expect(css).toContain('@media print')
  })

  it('章节顺序与计数:h1 唯一,h2/h3 与 Markdown 章节一一对应,表格行数一致且 #N 可见', () => {
    const d = doc(exportEvidenceHtml(input))
    expect(d.querySelectorAll('h1')).toHaveLength(1)
    expect(d.querySelector('h1')?.textContent).toBe('故障分析报告 · 事件 2/5')
    const h2s = [...d.querySelectorAll('h2')].map((h) => h.textContent ?? '')
    expect(h2s).toEqual(['概要', '事件卡', '故障阶段', '关键报文链', '序列空间摘要', '降级说明'])
    const h3s = [...d.querySelectorAll('h3')].map((h) => h.textContent ?? '')
    expect(h3s).toEqual(['观察 Observed', '推断 Inference(置信度 medium)', '限制 Limitations'])
    // 观察行:packet number 以 #N 文本直接可见(可定位原报文)
    const obsRows = d.querySelectorAll('table.obs tbody tr')
    expect(obsRows).toHaveLength(2)
    expect(obsRows[0]?.querySelectorAll('td')[0]?.textContent).toBe('#6')
    expect(obsRows[1]?.querySelectorAll('td')[0]?.textContent).toBe('#11')
    // 阶段行与关键报文行
    expect(d.querySelectorAll('table.stages tbody tr')).toHaveLength(2)
    const keyRows = d.querySelectorAll('table.keys tbody tr')
    expect(keyRows).toHaveLength(2)
    expect(keyRows[0]?.querySelectorAll('td')[0]?.textContent).toBe('#6')
    expect(keyRows[0]?.querySelectorAll('td')[1]?.textContent).toBe('→')
    expect(keyRows[1]?.querySelectorAll('td')[1]?.textContent).toBe('←')
  })

  it('概要承载抓包文件/会话/结论/恢复状态;事件卡承载类型/严重度/缺口', () => {
    const d = doc(exportEvidenceHtml(input))
    const text = d.body.textContent ?? ''
    for (const s of ['VDI_202608.pcapng', '10.0.0.1:1234 ↔ 93.184.216.34:443', '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium', '已恢复']) {
      expect(text).toContain(s)
    }
    const firstCells = [...d.querySelectorAll('table.facts tbody tr')].map((tr) => tr.querySelectorAll('td')[0]?.textContent ?? '')
    expect(firstCells).toContain('抓包文件')
    expect(firstCells).toContain('会话')
    expect(firstCells).toContain('结论')
    expect(firstCells).toContain('恢复状态')
    const cardCells = [...d.querySelectorAll('table.card tbody tr')].map((tr) => tr.querySelectorAll('td')[0]?.textContent ?? '')
    expect(cardCells).toContain('类型')
    expect(cardCells).toContain('严重度')
    expect(cardCells).toContain('缺口')
  })

  it('序列空间摘要:图形视窗取整、缺口取全量 allGaps、SACK 块数与截断提示', () => {
    const vm = makeVm()
    // 图形视窗只覆盖到 501;视窗外还有一个 1500–1601 的缺口 —— 必须列全,不得少报
    vm.seqSpace.gaps = [[101, 201]]
    vm.allGaps = [
      [101, 201],
      [1500, 1601],
    ]
    vm.seqSpace.axisMin = 0.4
    vm.seqSpace.axisMax = 500.6
    // 100 块触发渲染上限提示
    vm.seqSpace.sackBlocks = Array.from({ length: 100 }, (_, i) => [i * 10, i * 10 + 1] as [number, number])
    const d = doc(exportEvidenceHtml({ ...input, vm }))
    const text = d.body.textContent ?? ''
    expect(text).toContain('图形视窗(聚焦缺口邻域)')
    expect(text).toContain('0–501')
    expect(text).toContain('101–201, 1500–1601')
    expect(text).toContain('100(截断至渲染上限)')
  })

  it('伪重传场景:无缺口写「无(伪重传类场景)」,未恢复文案,gapText 缺省时事件卡无缺口行', () => {
    const vm = makeVm()
    vm.card.recovered = false
    vm.card.gapText = undefined
    vm.seqSpace.gaps = []
    vm.allGaps = []
    const d = doc(exportEvidenceHtml({ ...input, vm }))
    const text = d.body.textContent ?? ''
    expect(text).toContain('无(伪重传类场景)')
    expect(text).toContain('未恢复(抓包范围内未见补齐)')
    // 事件卡(card 表)无缺口行;序列空间摘要表的「缺口」行仍在(值为「无」)
    const cardCells = [...d.querySelectorAll('table.card tbody tr')].map((tr) => tr.querySelectorAll('td')[0]?.textContent ?? '')
    expect(cardCells).not.toContain('缺口')
  })

  it('降级说明:任一为真时出现且三行措辞与 Markdown 逐字一致;全假时整节省略', () => {
    const d = doc(exportEvidenceHtml(input))
    expect(d.body.textContent ?? '').toContain('抓包从连接中途开始:流起始处的缺失不构成丢包证据')

    const vm = makeVm()
    vm.degraded = { unorderableInput: true, midStream: false, lengthUnavailable: true, noEvents: false }
    const d2 = doc(exportEvidenceHtml({ ...input, vm }))
    const text2 = d2.body.textContent ?? ''
    expect(text2).toContain('载荷长度不可用:相关字节数省略显示(绝不以 0 冒充)')
    expect(text2).toContain('序列空间存在无法定位的输入:分析仅供参考')

    const vm3 = makeVm()
    vm3.degraded = { unorderableInput: false, midStream: false, lengthUnavailable: false, noEvents: false }
    const h2s = [...doc(exportEvidenceHtml({ ...input, vm: vm3 })).querySelectorAll('h2')].map((h) => h.textContent ?? '')
    expect(h2s).not.toContain('降级说明')
  })

  it('同期应用层事件:传入时出现且限定措辞原样透传,不传/空数组时整节省略', () => {
    const appImpacts = [
      {
        appSummary: 'HTTP 响应 200',
        tcpKindLabel: '疑似丢包 / 延迟到达',
        statement: '「HTTP 响应 200」与 疑似丢包 / 延迟到达 时间窗重叠(±2s):同期现象,可能相关,不构成因果',
      },
    ]
    const d = doc(exportEvidenceHtml({ ...input, appImpacts }))
    const h2s = [...d.querySelectorAll('h2')].map((h) => h.textContent ?? '')
    expect(h2s).toContain('同期应用层事件(时间窗关联)')
    expect(d.body.textContent ?? '').toContain('同期现象,可能相关,不构成因果')

    const without = exportEvidenceHtml(input)
    expect(without).not.toContain('同期应用层事件')
    expect(exportEvidenceHtml({ ...input, appImpacts: [] })).not.toContain('同期应用层事件')
  })

  it('注入防护:statement/label/summary/gapText/roleBadge/fileName 载荷全实体转义,img/script 元素数为 0', () => {
    const vm = makeVm()
    const payload = '<img src=x onerror=alert(1)>'
    const scriptPayload = '<script>alert(1)</script>'
    const quoted = 'a"b\'c&d'
    vm.card.observations = [{ packetNumber: 6, statement: `${payload}${quoted}` }]
    vm.card.gapText = `${scriptPayload}${quoted}`
    vm.keyPackets = [
      { packetNumber: 7, time: 0.05, dir: 'c2s', label: scriptPayload, stageIndex: 1, roleBadge: `${payload}${quoted}` },
    ]
    vm.stages = [
      { label: payload, summary: scriptPayload, fromPacket: 4, toPacket: 5, startTime: 0.03, endTime: 0.04, observationRefs: [], t0: 0, t1: 0.2 },
    ]
    const evil = { ...input, fileName: `${payload}.pcapng`, conversationLabel: `${scriptPayload} ↔ x`, vm }
    const html = exportEvidenceHtml(evil)
    const d = doc(html)
    // 无注入元素:img/script 均不得作为 DOM 元素出现
    expect(d.querySelectorAll('img')).toHaveLength(0)
    expect(d.querySelectorAll('script')).toHaveLength(0)
    // 载荷以实体形式出现在 textContent(解码后即原文),不构成可执行内容
    const text = d.body.textContent ?? ''
    expect(text).toContain('onerror=alert(1)')
    expect(text).toContain('<script>alert(1)</script>')
    expect(text).toContain(quoted)
    // 原始文本不含可执行标签;引号与 & 已实体化
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<script')
    expect(html).toContain('&quot;')
    expect(html).toContain('&#39;')
    expect(html).toContain('&amp;')
  })

  it('确定性:同输入两次调用逐字一致;零脚本、零远程资源(无 http(s)://)', () => {
    const a = exportEvidenceHtml(input)
    const b = exportEvidenceHtml(input)
    expect(a).toBe(b)
    expect(a).not.toMatch(/https?:\/\//)
    expect(a).not.toContain('<script')
  })

  it('数据保真红线:正常参考侧示意绝不进入报告(页脚口径声明除外)', () => {
    const html = exportEvidenceHtml(input)
    expect(html).not.toContain('数据段 1')
    expect(html).not.toContain('按序列顺序连续发送')
    expect(html).toContain('仅含实际故障侧证据;正常参考为解释性示意,不在本报告内')
  })

  it('defaultEvidenceHtmlName:ASCII 安全、.html 后缀、风格对齐 defaultCompareReportName', () => {
    expect(defaultEvidenceHtmlName('10.0.0.1:1234 ↔ 93.184.216.34:443', 3)).toMatch(/^fault_[\w.-]+_ev3\.html$/)
    expect(defaultEvidenceHtmlName('中文会话 <>:1', 1)).not.toMatch(/[\u4e00-\u9fff<>]/)
    // 清洗后为空时回退占位名,保证文件名永远合法
    expect(defaultEvidenceHtmlName('', 1)).toBe('fault_report_ev1.html')
  })
})

describe('语义一致性抽查 — 同一 fixture 下 HTML 与 Markdown 同口径', () => {
  it('观察/阶段/关键报文的行数与缺口清单文本一致', () => {
    const md = exportCompareReport(input)
    const d = doc(exportEvidenceHtml(input))
    expect(mdRowCount(md, '### 观察 Observed', '### 推断')).toBe(d.querySelectorAll('table.obs tbody tr').length)
    expect(mdRowCount(md, '## 故障阶段', '## 关键报文链')).toBe(d.querySelectorAll('table.stages tbody tr').length)
    expect(mdRowCount(md, '## 关键报文链', '## 序列空间摘要')).toBe(d.querySelectorAll('table.keys tbody tr').length)
    // 缺口清单取全量 allGaps:同一口径、同一文本
    expect(htmlGapValue(d)).toBe('101–201')
    expect(md).toContain('- 缺口: 101–201')
  })

  it('视窗外缺口同样不少报:allGaps 全量文本在 MD 与 HTML 中逐字一致', () => {
    const vm = makeVm()
    vm.seqSpace.gaps = [[101, 201]]
    vm.allGaps = [
      [101, 201],
      [1500, 1601],
    ]
    const md = exportCompareReport({ ...input, vm })
    const d = doc(exportEvidenceHtml({ ...input, vm }))
    expect(htmlGapValue(d)).toBe('101–201, 1500–1601')
    expect(md).toContain('101–201, 1500–1601')
  })
})
