import type { CompareReportModel } from './report'

/**
 * 对照报告渲染器:Markdown / HTML(与 evidenceHtml.ts 同风格)。
 *
 * 硬性约束:
 * - **单文件离线**:完整文档 + 内联 <style>,零脚本、零远程资源、零外部字体/图片;
 * - **注入防护**:抓包内容(报文标签/文件名/事件文本)是不可信输入,所有插值字符串
 *   必须过 htmlEscape(& < > " '),文档中永不出现可执行标签;
 * - **确定性**:纯函数,不内嵌时间戳 —— 同一输入两次渲染逐字一致。
 */

/** HTML 实体转义:& 必须最先替换(否则后续替换会把 &amp; 的 & 再转一次) */
function htmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 打印样式:与 evidenceHtml 同一族(@page A4、thead 跨页重复、行防断页、系统字体) */
const PRINT_CSS = [
  '@page { size: A4; margin: 18mm 15mm; }',
  'body { font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif; color: #111; line-height: 1.6; margin: 24px auto; max-width: 960px; padding: 0 16px; }',
  'h1 { font-size: 1.6em; margin: 0 0 8px; }',
  'h2 { font-size: 1.2em; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; break-after: avoid; page-break-after: avoid; }',
  'h3 { font-size: 1.05em; margin: 18px 0 6px; break-after: avoid; page-break-after: avoid; }',
  'table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 0.9em; }',
  'th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; vertical-align: top; }',
  'thead { display: table-header-group; }',
  'th { background: #efefef; }',
  'tr { break-inside: avoid; page-break-inside: avoid; }',
  'p { margin: 6px 0; }',
  'p.warn { color: #a33; }',
  'p.meta { color: #555; margin: 0 0 4px; }',
  'p.empty { color: #555; font-style: italic; }',
  'ul { padding-left: 1.4em; } li { margin: 4px 0; break-inside: avoid; }',
  'p.footer { color: #777; font-style: italic; margin-top: 32px; }',
  '@media print { body { margin: 0; max-width: none; padding: 0; } }',
].join('\n')

/** 结构化表格:表头与所有单元格统一过 htmlEscape —— 数字也一并转义(无副作用),
 *  保证「所有插值必须转义」是结构性事实而非逐处记忆 */
function table(headers: string[], rows: string[][], cls: string): string {
  const th = headers.map((h) => '<th>' + htmlEscape(h) + '</th>').join('')
  const trs = rows
    .map((r) => '<tr>' + r.map((c) => '<td>' + htmlEscape(c) + '</td>').join('') + '</tr>')
    .join('')
  return (
    '<table class="' + cls + '"><thead><tr>' + th + '</tr></thead>' + (trs ? '<tbody>' + trs + '</tbody>' : '') + '</table>'
  )
}

/** Markdown 单元格转义:与 exportTranscript.mdCell 同一注入防线 —— 抓包内容是不可信输入。
 *  竖线是表格结构字符必须转义,换行折叠为空格;`<`/`>` 是 Markdown 渲染器注入口
 *  (Typora/Obsidian/marked 系会渲染原始 HTML),必须整体剥除防 <img onerror> 透传;
 *  `&` 实体转义,防 &amp;/&lt; 等字面量被渲染器二次解码产生歧义 —— 先于其它替换做,
 *  否则后续会把 &amp; 的 & 再转一次。内部反引号前置反斜杠转义(替换串用 BS+BT
 *  显式构造:字面量 '\\`' 实际只是反引号,是静默失效的转义)。
 *  与 exportTranscript.mdCell 输出形态一致,保证全库 Markdown 单元格同口径。 */
const MD_BS = String.fromCharCode(92) // 反斜杠
const MD_BT = String.fromCharCode(96) // 反引号

function mdCell(s: string): string {
  const noAngle = s.replace(/&/g, '&amp;').replace(/[<>]/g, '')
  return noAngle.split(MD_BT).join(MD_BS + MD_BT).split('|').join(MD_BS + '|').replace(/\r?\n/g, ' ')
}

/** 标题/行内文本的轻量转义:剥尖括号(防 HTML 注入)、拍平换行。 */
function mdText(s: string): string {
  return s.replace(/[<>]/g, '').replace(/\r?\n/g, ' ')
}

function mdTable(headers: string[], rows: string[][]): string {
  const head = '| ' + headers.map(mdCell).join(' | ') + ' |'
  const sep = '|' + headers.map(() => ' --- |').join('')
  const body = rows.map((r) => '| ' + r.map(mdCell).join(' | ') + ' |')
  return [head, sep, ...body].join('\n')
}

/** 时刻格式:epoch 秒固定 3 位小数(毫秒精度;容差即毫秒级,展示对齐判定口径) */
function fmtEpoch(t: number): string {
  return t.toFixed(3)
}

const SIDE_LABEL: Record<string, string> = { A: '仅 A 见到', B: '仅 B 见到', AB: '两侧均见' }
const ONLY_IN_LABEL: Record<string, string> = { A: '仅 A', B: '仅 B', both: '两侧' }

export function renderCompareReportMd(model: CompareReportModel): string {
  const out: string[] = []
  out.push(`# ${mdText(model.title)}`)
  out.push('')
  out.push('## 概要')
  out.push('')
  out.push(mdTable(['项目', '值'], model.summary.map((f) => [f.label, f.value])))
  out.push('')

  model.pairs.forEach((p, i) => {
    out.push(`## 会话对 ${i + 1}:${mdText(p.endpointLabel)}`)
    out.push('')
    const s = p.statsRow.stats
    out.push(`### 报文对照(${mdText(p.statsRow.label)})`)
    out.push('')
    out.push(mdTable(['指标', 'A 侧', 'B 侧'], [
      ['包数', String(s.countA), String(s.countB)],
      ['字节', String(s.bytesA), String(s.bytesB)],
    ]))
    out.push('')
    out.push('### 事件差异')
    out.push('')
    if (p.eventRows.length === 0) {
      out.push('无事件差异。')
    } else {
      out.push(mdTable(
        ['事件类型', '缺口区间', '恢复状态', '出现侧'],
        p.eventRows.map((e) => [e.kind, e.gapText, e.recovered ? '已恢复' : '未恢复', ONLY_IN_LABEL[e.onlyIn] ?? e.onlyIn]),
      ))
    }
    out.push('')
    out.push('### 结论辅助(观察层提示)')
    out.push('')
    if (p.verdicts.length === 0) {
      out.push('无。')
    } else {
      out.push(mdTable(
        ['级别', '结论'],
        p.verdicts.map((v) => [v.severity === 'warn' ? 'warn' : 'info', v.statement]),
      ))
    }
    out.push('')
    out.push(`### 时间线${p.timelineTruncated ? '(已截断:保留最早与最晚各半)' : ''}`)
    out.push('')
    if (p.timelineRows.length === 0) {
      out.push('无可列报文。')
    } else {
      out.push(mdTable(
        ['时刻 (epoch s)', '观测', 'A #', 'A 信息', 'B #', 'B 信息'],
        p.timelineRows.map((r) => [
          fmtEpoch(r.timeEpoch),
          SIDE_LABEL[r.side] ?? r.side,
          r.numberA != null ? `#${r.numberA}` : '—',
          r.infoA ?? '—',
          r.numberB != null ? `#${r.numberB}` : '—',
          r.infoB ?? '—',
        ]),
      ))
    }
    out.push('')
  })

  out.push('## 未匹配会话')
  out.push('')
  if (model.unmatchedRows.length === 0) {
    out.push('全部会话均已对齐。')
  } else {
    out.push(mdTable(
      ['侧', '端点对', '包数'],
      model.unmatchedRows.map((u) => [u.side, u.label, String(u.packetCount)]),
    ))
  }
  out.push('')
  out.push('## 口径与限制')
  out.push('')
  out.push(...model.methodology.map((l) => `- ${l}`))
  out.push('')
  out.push('由 pUI 导出 · 双观测点对照(两侧独立分析,仅对齐与比较结论)')
  out.push('')
  return out.join('\n')
}

export function renderCompareReportHtml(model: CompareReportModel): string {
  const parts: string[] = []
  parts.push('<h1>' + htmlEscape(model.title) + '</h1>')

  parts.push('<h2>概要</h2>')
  parts.push(table(['项目', '值'], model.summary.map((f) => [f.label, f.value]), 'facts'))

  model.pairs.forEach((p, i) => {
    parts.push('<h2>' + htmlEscape(`会话对 ${i + 1}:${p.endpointLabel}`) + '</h2>')

    const s = p.statsRow.stats
    parts.push('<h3>' + htmlEscape(`报文对照(${p.statsRow.label})`) + '</h3>')
    parts.push(table(
      ['指标', 'A 侧', 'B 侧'],
      [
        ['包数', String(s.countA), String(s.countB)],
        ['字节', String(s.bytesA), String(s.bytesB)],
      ],
      'stats',
    ))

    parts.push('<h3>事件差异</h3>')
    if (p.eventRows.length === 0) {
      parts.push('<p class="empty">无事件差异。</p>')
    } else {
      parts.push(table(
        ['事件类型', '缺口区间', '恢复状态', '出现侧'],
        p.eventRows.map((e) => [e.kind, e.gapText, e.recovered ? '已恢复' : '未恢复', ONLY_IN_LABEL[e.onlyIn] ?? e.onlyIn]),
        'events',
      ))
    }

    parts.push('<h3>结论辅助(观察层提示)</h3>')
    if (p.verdicts.length === 0) {
      parts.push('<p class="empty">无。</p>')
    } else {
      parts.push(table(
        ['级别', '结论'],
        p.verdicts.map((v) => [v.severity, v.statement]),
        'verdicts',
      ))
    }

    parts.push('<h3>时间线</h3>')
    if (p.timelineTruncated) {
      parts.push('<p class="meta">已截断:保留最早与最晚各半(巨型会话渲染护栏)。</p>')
    }
    if (p.timelineRows.length === 0) {
      parts.push('<p class="empty">无可列报文。</p>')
    } else {
      parts.push(table(
        ['时刻 (epoch s)', '观测', 'A #', 'A 信息', 'B #', 'B 信息'],
        p.timelineRows.map((r) => [
          fmtEpoch(r.timeEpoch),
          SIDE_LABEL[r.side] ?? r.side,
          r.numberA != null ? `#${r.numberA}` : '—',
          r.infoA ?? '—',
          r.numberB != null ? `#${r.numberB}` : '—',
          r.infoB ?? '—',
        ]),
        'timeline',
      ))
    }
  })

  parts.push('<h2>未匹配会话</h2>')
  if (model.unmatchedRows.length === 0) {
    parts.push('<p class="empty">全部会话均已对齐。</p>')
  } else {
    parts.push(table(
      ['侧', '端点对', '包数'],
      model.unmatchedRows.map((u) => [u.side, u.label, String(u.packetCount)]),
      'unmatched',
    ))
  }

  parts.push('<h2>口径与限制</h2>')
  parts.push('<ul>' + model.methodology.map((l) => '<li>' + htmlEscape(l) + '</li>').join('') + '</ul>')

  parts.push('<p class="footer">由 pUI 导出 · 双观测点对照(两侧独立分析,仅对齐与比较结论)</p>')

  return [
    '<!doctype html>',
    '<html lang="zh-CN">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>' + htmlEscape(model.title) + '</title>',
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
