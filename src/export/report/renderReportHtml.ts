import type { ReportModel } from './reportModel'
import { REPORT_SECTIONS, packetCell, parseTranscriptTableLines } from './reportModel'

/**
 * 会话分析报告 → 独立 HTML(纯函数、确定性),供 WebView 加载后「打印 → 另存为 PDF」。
 * - 完整文档:<!doctype html> / lang="zh-CN" / 内联 <style>,无外部资源,可离线打开;
 * - 打印样式:@page 页边距、表格边框、thead 跨页重复(display: table-header-group)、
 *   行级防分页断行(break-inside: avoid)、标题不与正文断开(break-after: avoid);
 * - XSS 防线:抓包内容先经模型侧 mdCell(展示层已剥尖括号),此处再对**所有**插值统一
 *   escapeHtml(<>&"),双重保险 —— 文档中永不出现可执行标签。
 */

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function table(headers: string[], rows: string[][], cls: string): string {
  const th = headers.map((h) => '<th>' + esc(h) + '</th>').join('')
  const trs = rows
    .map((r) => '<tr>' + r.map((c) => '<td>' + esc(c) + '</td>').join('') + '</tr>')
    .join('')
  return (
    '<table class="' + cls + '"><thead><tr>' + th + '</tr></thead>' + (trs ? '<tbody>' + trs + '</tbody>' : '') + '</table>'
  )
}

const PRINT_CSS = [
  '@page { size: A4; margin: 18mm 15mm; }',
  'body { font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif; color: #111; line-height: 1.6; margin: 24px auto; max-width: 860px; padding: 0 16px; }',
  'h1 { font-size: 1.6em; margin: 0 0 8px; }',
  'h2 { font-size: 1.2em; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; break-after: avoid; page-break-after: avoid; }',
  'h3 { font-size: 1.05em; margin: 18px 0 6px; break-after: avoid; page-break-after: avoid; }',
  'table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 0.9em; }',
  'th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; vertical-align: top; }',
  'thead { display: table-header-group; }', // 打印跨页时每页重复表头
  'th { background: #efefef; }',
  'tr { break-inside: avoid; page-break-inside: avoid; }', // 行内不跨页断开
  'p.meta { color: #555; margin: 0 0 4px; }',
  'p.empty { color: #555; font-style: italic; }',
  'ul { padding-left: 1.4em; } li { margin: 4px 0; break-inside: avoid; }',
  'p.footer { color: #777; font-style: italic; margin-top: 32px; }',
  '@media print { body { margin: 0; max-width: none; padding: 0; } }',
].join('\n')

export function renderReportHtml(m: ReportModel): string {
  const parts: string[] = []
  parts.push('<h1>' + esc(m.title) + '</h1>')
  if (m.generatedAt !== null) {
    parts.push('<p class="meta">生成时间: ' + esc(m.generatedAt) + '</p>')
  }

  parts.push('<h2>' + esc(REPORT_SECTIONS.summary) + '</h2>')
  parts.push(table(['项目', '值'], m.summary.map((f) => [f.label, f.value]), 'facts'))

  parts.push('<h2>' + esc(REPORT_SECTIONS.findings) + '</h2>')
  if (m.findings.note !== null) {
    parts.push('<p class="meta">' + esc(m.findings.note) + '</p>')
  }
  if (m.findings.issues.length) {
    parts.push('<h3>' + esc(REPORT_SECTIONS.issues) + '</h3>')
    parts.push(
      table(
        ['类型', '说明', '关联包号'],
        m.findings.issues.map((i) => [i.type, i.message, packetCell(i.packetNumber)]),
        'issues',
      ),
    )
  }
  if (m.findings.stats.length) {
    parts.push('<h3>' + esc(REPORT_SECTIONS.stats) + '</h3>')
    parts.push(
      table(
        ['标记', '次数', '首个样本'],
        m.findings.stats.map((s) => [s.flag, String(s.count), '#' + s.firstPacket]),
        'stats',
      ),
    )
  }

  parts.push('<h2>' + esc(REPORT_SECTIONS.timeline) + '</h2>')
  parts.push('<p class="meta">当前模式: ' + esc(m.timeline.modeLabel) + '</p>')
  if (m.timeline.tableLines.length) {
    // 模型承载的 transcriptTableLines 原样输出,此处解析为结构化表格(转义还原见 parseTranscriptTableLines)
    const t = parseTranscriptTableLines(m.timeline.tableLines)
    parts.push(table(t.header, t.rows, 'timeline'))
  } else if (m.timeline.emptyText !== null) {
    parts.push('<p class="empty">' + esc(m.timeline.emptyText) + '</p>')
  }

  parts.push('<h2>' + esc(REPORT_SECTIONS.methodology) + '</h2>')
  parts.push('<ul>' + m.methodology.map((p) => '<li>' + esc(p) + '</li>').join('') + '</ul>')

  parts.push('<p class="footer">由 pUI 导出</p>')

  return [
    '<!doctype html>',
    '<html lang="zh-CN">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>' + esc(m.title) + '</title>',
    '<style>',
    PRINT_CSS,
    '</style>',
    '</head>',
    '<body>',
    ...parts,
    '</body>',
    '</html>',
    '',
  ].join('\n')
}
