import type { CompareReportInput } from './exportCompareReport'

/**
 * M7 收尾:事件级单文件离线 HTML 证据报告(供「打印 → 另存为 PDF」与离线归档)。
 *
 * 与 exportCompareReport(Markdown 证据)同源同口径:同一 CompareReportInput,
 * 章节一一对应、顺序一致(语义一致性有测试钉住),只导出**实际故障侧**证据,
 * 右栏「正常参考」示意永不进入报告。
 *
 * 硬性约束:
 * - **单文件离线**:完整文档 + 内联 <style>,零脚本、零远程资源、零外部字体/图片 ——
 *   证据文件要在隔离环境取证机器上可离线打开,任何网络引用都会失真或泄露访问痕迹;
 * - **注入防护**:抓包内容(报文标签/引擎文案/文件名)是不可信输入,所有插值字符串
 *   必须过 htmlEscape(& < > " '),文档中永不出现可执行标签(DOMParser 测试钉住);
 * - **确定性**:纯函数,不内嵌时间戳 —— 同一输入两次导出逐字节一致(取证可复现)。
 */

/** HTML 实体转义:& 必须最先替换(否则后续替换会把 &amp; 的 & 再转一次);
 *  单引号也转义(&#39;),防属性上下文(虽然当前全在元素内容,规则统一更不易漏) */
function htmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 打印样式:A4 边距(@page)、thead 跨页重复(table-header-group)、行防断页
 *  (break-inside: avoid)、标题不与正文断开(break-after: avoid);
 *  字体只用系统内置中文黑体族,不引外部字体(离线红线)。 */
const PRINT_CSS = [
  '@page { size: A4; margin: 18mm 15mm; }',
  'body { font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif; color: #111; line-height: 1.6; margin: 24px auto; max-width: 860px; padding: 0 16px; }',
  'h1 { font-size: 1.6em; margin: 0 0 8px; }',
  'h2 { font-size: 1.2em; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; break-after: avoid; page-break-after: avoid; }',
  'h3 { font-size: 1.05em; margin: 18px 0 6px; break-after: avoid; page-break-after: avoid; }',
  'table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 0.9em; }',
  'th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; vertical-align: top; }',
  // 打印跨页时每页重复表头
  'thead { display: table-header-group; }',
  'th { background: #efefef; }',
  // 行内不跨页断开(观察/报文行断在两页会破坏证据可读性)
  'tr { break-inside: avoid; page-break-inside: avoid; }',
  'p { margin: 6px 0; }',
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

export function exportEvidenceHtml(input: CompareReportInput): string {
  const { fileName, conversationLabel, eventNo, eventTotal, vm } = input
  const parts: string[] = []
  const title = `故障分析报告 · 事件 ${eventNo}/${eventTotal}`

  // 1) h1 标题 + 2) 概要(与 Markdown 报告开头的要点列表同四项)
  parts.push('<h1>' + htmlEscape(title) + '</h1>')
  parts.push('<h2>概要</h2>')
  parts.push(
    table(
      ['项目', '值'],
      [
        ['抓包文件', fileName],
        ['会话', conversationLabel],
        ['结论', vm.headline],
        ['恢复状态', vm.card.recovered ? '已恢复' : '未恢复(抓包范围内未见补齐)'],
      ],
      'facts',
    ),
  )

  // 3) 事件卡(类型/严重度/缺口;gapText 为空 = 伪重传类无缺口,行整体省略)
  parts.push('<h2>事件卡</h2>')
  const cardRows: string[][] = [
    ['类型', vm.card.kindLabel],
    ['严重度', vm.card.severity],
  ]
  if (vm.card.gapText) cardRows.push(['缺口', vm.card.gapText])
  parts.push(table(['项目', '值'], cardRows, 'card'))

  // 4) 观察/推断/限制(与 Markdown 的 ### 小节同序同文案;观察行 #N 直接可见)
  parts.push('<h3>观察 Observed</h3>')
  parts.push(
    table(
      ['报文', '观察'],
      vm.card.observations.map((o) => [`#${o.packetNumber}`, o.statement]),
      'obs',
    ),
  )
  parts.push('<h3>推断 Inference(置信度 ' + htmlEscape(vm.card.inference.confidence) + ')</h3>')
  parts.push('<p>' + htmlEscape(vm.card.inference.statement) + '</p>')
  parts.push('<h3>限制 Limitations</h3>')
  parts.push('<ul>' + vm.card.limitations.map((lim) => '<li>' + htmlEscape(lim) + '</li>').join('') + '</ul>')

  // 5) 故障阶段(时刻固定 toFixed(3),与 Markdown 报告同精度)
  parts.push('<h2>故障阶段</h2>')
  parts.push(
    table(
      ['#', '阶段', '报文区间', '时刻(s)', '要点'],
      vm.stages.map((s, i) => [
        String(i + 1),
        s.label,
        `#${s.fromPacket}–#${s.toPacket}`,
        `${s.startTime.toFixed(3)}–${s.endTime.toFixed(3)}`,
        s.summary,
      ]),
      'stages',
    ),
  )

  // 6) 关键报文链(#N 直接可见;方向箭头与 Markdown 同符;c2s → / s2c ←)
  parts.push('<h2>关键报文链</h2>')
  parts.push(
    table(
      ['#', '方向', '概要', '角色'],
      vm.keyPackets.map((k) => [`#${k.packetNumber}`, k.dir === 'c2s' ? '→' : '←', k.label, k.roleBadge ?? '']),
      'keys',
    ),
  )

  // 7) 序列空间摘要。缺口清单取全量(vm.allGaps):seqSpace.gaps 已按图形视窗裁剪,
  //    直接导出会少报视窗外的缺口 —— 证据宁可列全,不可静默丢弃(与 Markdown/JSON
  //    证据同一口径;旧缓存视图模型无 allGaps 时回退)
  const sq = vm.seqSpace
  const gapList = vm.allGaps ?? sq.gaps
  parts.push('<h2>序列空间摘要</h2>')
  parts.push(
    table(
      ['项目', '值'],
      [
        ['图形视窗(聚焦缺口邻域)', `${Math.round(sq.axisMin)}–${Math.round(sq.axisMax)}`],
        [
          '缺口',
          gapList.length
            ? gapList.map(([a, b]) => `${Math.round(a)}–${Math.round(b)}`).join(', ')
            : '无(伪重传类场景)',
        ],
        ['SACK 块(合并后)', `${sq.sackBlocks.length}${sq.sackBlocks.length >= 100 ? '(截断至渲染上限)' : ''}`],
      ],
      'seqspace',
    ),
  )

  // 8) 降级说明(仅任一为真时出现;三行措辞与 Markdown 报告逐字一致,有测试钉住)
  if (vm.degraded.midStream || vm.degraded.unorderableInput || vm.degraded.lengthUnavailable) {
    parts.push('<h2>降级说明</h2>')
    const lines: string[] = []
    if (vm.degraded.midStream) lines.push('抓包从连接中途开始:流起始处的缺失不构成丢包证据')
    if (vm.degraded.lengthUnavailable) lines.push('载荷长度不可用:相关字节数省略显示(绝不以 0 冒充)')
    if (vm.degraded.unorderableInput) lines.push('序列空间存在无法定位的输入:分析仅供参考')
    parts.push('<ul>' + lines.map((l) => '<li>' + htmlEscape(l) + '</li>').join('') + '</ul>')
  }

  // 9) 同期应用层关联(可选;措辞来自 correlateImpacts,已含"可能相关,不构成因果"限定,原样透传)
  if (input.appImpacts && input.appImpacts.length > 0) {
    parts.push('<h2>同期应用层事件(时间窗关联)</h2>')
    parts.push('<ul>' + input.appImpacts.map((imp) => '<li>' + htmlEscape(imp.statement) + '</li>').join('') + '</ul>')
  }

  // 10) 页脚说明(与 Markdown 尾注同义:口径声明,非数据)
  parts.push('<p class="footer">由 pUI 导出 · 仅含实际故障侧证据;正常参考为解释性示意,不在本报告内</p>')

  return [
    '<!doctype html>',
    '<html lang="zh-CN">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>' + htmlEscape(title) + '</title>',
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

/** 导出文件名:与 defaultCompareReportName 同风格(fault_<safe>_ev<N>.html);
 *  非 ASCII(中文/全角/↔ 等)与文件系统危险字符统一压成下划线,保证跨平台可落盘 */
export function defaultEvidenceHtmlName(conversationLabel: string, eventNo: number): string {
  const safe = conversationLabel.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
  return `fault_${safe || 'report'}_ev${eventNo}.html`
}
