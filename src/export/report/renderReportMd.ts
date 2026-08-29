import type { ReportModel } from './reportModel'
import { REPORT_SECTIONS, packetCell } from './reportModel'
import { mdCell } from '../exportTranscript'

/**
 * 会话分析报告 → Markdown 渲染(纯函数、确定性)。
 * 与叙述导出同一注入防线:表格单元格一律 mdCell 转义(报文 info/分析标记是抓包文件里的
 * 不可信内容,防表格被竖线/换行破坏、防下游 Markdown 渲染器注入 HTML);
 * 非单元格行内文本(标题/说明)走 mdText 轻量转义(剥尖括号、拍平换行)。
 * 「三、会话时序」直接承载模型里的 transcriptTableLines 原样输出,零改写。
 */

/** 非单元格的行内文本:剥尖括号(防 HTML 注入)、拍平换行(与对照页报告同口径) */
function mdText(s: string): string {
  return s.replace(/[<>]/g, '').replace(/\r?\n/g, ' ')
}

export function renderReportMd(m: ReportModel): string {
  const L: string[] = []
  L.push('# ' + mdText(m.title))
  L.push('')
  if (m.generatedAt !== null) {
    L.push('- 生成时间: ' + mdText(m.generatedAt))
    L.push('')
  }

  L.push('## ' + REPORT_SECTIONS.summary)
  L.push('')
  L.push('| 项目 | 值 |')
  L.push('|---|---|')
  for (const f of m.summary) {
    L.push('| ' + mdCell(f.label) + ' | ' + mdCell(f.value) + ' |')
  }
  L.push('')

  L.push('## ' + REPORT_SECTIONS.findings)
  L.push('')
  if (m.findings.note !== null) {
    L.push(mdText(m.findings.note))
    L.push('')
  }
  if (m.findings.issues.length) {
    L.push('### ' + REPORT_SECTIONS.issues)
    L.push('')
    L.push('| 类型 | 说明 | 关联包号 |')
    L.push('|---|---|---|')
    for (const i of m.findings.issues) {
      // type 为固定枚举值(非抓包内容)保持原样便于检索;message 是自由文本,走 mdCell
      L.push('| ' + mdText(i.type) + ' | ' + mdCell(i.message) + ' | ' + packetCell(i.packetNumber) + ' |')
    }
    L.push('')
  }
  if (m.findings.stats.length) {
    L.push('### ' + REPORT_SECTIONS.stats)
    L.push('')
    L.push('| 标记 | 次数 | 首个样本 |')
    L.push('|---|---|---|')
    for (const s of m.findings.stats) {
      // flag 来自抓包文件(tshark 标签),与其他不可信单元格一致走 mdCell;计数/包号为计算值
      L.push('| ' + mdCell(s.flag) + ' | ' + s.count + ' | #' + s.firstPacket + ' |')
    }
    L.push('')
  }

  L.push('## ' + REPORT_SECTIONS.timeline)
  L.push('')
  L.push('当前模式: ' + mdText(m.timeline.modeLabel))
  L.push('')
  if (m.timeline.tableLines.length) {
    // transcriptTableLines 原样输出(含表头/分隔行),与叙述导出同源零改写
    L.push(...m.timeline.tableLines)
    L.push('')
  } else if (m.timeline.emptyText !== null) {
    L.push('_' + mdText(m.timeline.emptyText) + '_')
    L.push('')
  }

  L.push('## ' + REPORT_SECTIONS.methodology)
  L.push('')
  for (const p of m.methodology) {
    L.push('- ' + mdText(p))
  }
  L.push('')
  L.push('_由 pUI 导出_')
  return L.join('\n')
}
