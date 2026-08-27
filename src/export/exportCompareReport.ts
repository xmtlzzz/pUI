import type { CompareViewModel } from '../m4/viewModel'

/**
 * 对照页证据导出(Markdown)。口径(用户裁定 2026-08-27):
 * - 只导出**实际故障侧**:事件证据链(观察/推断/限制)、阶段、关键报文 —— 可进入报告;
 * - 右栏「正常参考」是解释性示意,**永不进入导出**(数据保真红线,有测试钉住);
 * - 报文号/序号/字节是抓包内的事实,如实导出;所有文本字段做 Markdown 注入转义。
 */

/** Markdown 单元格转义:抓包内容(标签/文案引用的字段值)是不可信输入。
 *  反引号/竖线前置反斜杠(替换串用 BS+BT 显式构造 —— 字面量 '\\`' 实际只是反引号,
 *  是静默失效的转义,exportTranscript 的旧实现同样中招);尖括号整体剥除。 */
const BS = String.fromCharCode(92) // 反斜杠
const BT = String.fromCharCode(96) // 反引号
function mdCell(s: string): string {
  const noAngle = s.replace(/[<>]/g, '')
  return BT + noAngle.split(BT).join(BS + BT).split('|').join(BS + '|').replace(/\r?\n/g, ' ') + BT
}

/** 列表/段落用轻量转义:剥尖括号(防 HTML 注入)、拍平换行;不加代码包裹 */
function mdText(s: string): string {
  return s.replace(/[<>]/g, '').replace(/\r?\n/g, ' ')
}

export interface CompareReportInput {
  /** 抓包文件名(报告溯源) */
  fileName: string
  /** 会话标识 "client ↔ server" */
  conversationLabel: string
  /** 当前导出的事件在切换器中的序号(1 起)与总数 */
  eventNo: number
  eventTotal: number
  vm: CompareViewModel
}

export function exportCompareReport(input: CompareReportInput): string {
  const { fileName, conversationLabel, eventNo, eventTotal, vm } = input
  const L: string[] = []
  L.push(`# 故障分析报告 · 事件 ${eventNo}/${eventTotal}`)
  L.push('')
  L.push(`- 抓包文件: ${mdText(fileName)}`)
  L.push(`- 会话: ${mdText(conversationLabel)}`)
  L.push(`- 结论: ${mdText(vm.headline)}`)
  L.push(`- 恢复状态: ${vm.card.recovered ? '已恢复' : '**未恢复**(抓包范围内未见补齐)'}`)
  L.push('')

  L.push('## 事件卡')
  L.push('')
  L.push(`- 类型: ${mdText(vm.card.kindLabel)} · 严重度 ${mdText(vm.card.severity)}`)
  if (vm.card.gapText) L.push(`- 缺口: ${mdText(vm.card.gapText)}`)
  L.push('')

  L.push('### 观察 Observed')
  L.push('')
  L.push('| # | 报文 | 观察 |')
  L.push('|---|---|---|')
  for (const o of vm.card.observations) {
    L.push(`| ${o.packetNumber} | #${o.packetNumber} | ${mdCell(o.statement)} |`)
  }
  L.push('')
  L.push(`### 推断 Inference(置信度 ${mdText(vm.card.inference.confidence)})`)
  L.push('')
  L.push(mdText(vm.card.inference.statement))
  L.push('')
  L.push('### 限制 Limitations')
  L.push('')
  for (const lim of vm.card.limitations) L.push(`- ${mdText(lim)}`)
  L.push('')

  L.push('## 故障阶段')
  L.push('')
  L.push('| # | 阶段 | 报文 | 时刻(s) | 要点 |')
  L.push('|---|---|---|---|---|')
  vm.stages.forEach((s, i) => {
    L.push(
      `| ${i + 1} | ${mdCell(s.label)} | #${s.fromPacket}–#${s.toPacket} | ${s.startTime.toFixed(3)}–${s.endTime.toFixed(3)} | ${mdText(s.summary)} |`,
    )
  })
  L.push('')

  L.push('## 关键报文链')
  L.push('')
  L.push('| # | 方向 | 概要 | 角色 |')
  L.push('|---|---|---|---|')
  for (const k of vm.keyPackets) {
    L.push(`| ${k.packetNumber} | ${k.dir === 'c2s' ? '→' : '←'} | ${mdCell(k.label)} | ${k.roleBadge ? mdCell(k.roleBadge) : ''} |`)
  }
  L.push('')

  L.push('## 序列空间摘要')
  L.push('')
  const sq = vm.seqSpace
  L.push(`- 字节区间: ${Math.round(sq.axisMin)}–${Math.round(sq.axisMax)}`)
  if (sq.gaps.length) {
    L.push(`- 缺口: ${sq.gaps.map(([a, b]) => `${Math.round(a)}–${Math.round(b)}`).join(', ')}`)
  } else {
    L.push('- 缺口: 无(伪重传/窗口类场景)')
  }
  L.push(`- SACK 块(合并后): ${sq.sackBlocks.length}${sq.sackBlocks.length >= 100 ? '(截断至渲染上限)' : ''}`)
  L.push('')

  if (vm.degraded.midStream || vm.degraded.unorderableInput || vm.degraded.lengthUnavailable) {
    L.push('## 降级说明')
    L.push('')
    if (vm.degraded.midStream) L.push('- 抓包从连接中途开始:流起始处的缺失不构成丢包证据')
    if (vm.degraded.lengthUnavailable) L.push('- 载荷长度不可用:字节数以 unknown 处理')
    if (vm.degraded.unorderableInput) L.push('- 序列空间存在无法定位的输入:分析仅供参考')
    L.push('')
  }

  L.push('---')
  L.push('')
  L.push('_由 pUI 导出 · 仅含实际故障侧证据;正常参考为解释性示意,不在本报告内_')
  return L.join('\n')
}

/** 导出文件名:与现有 defaultPngName 风格一致的 ASCII 安全名 */
export function defaultCompareReportName(conversationLabel: string, eventNo: number): string {
  const safe = conversationLabel.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
  return `fault_${safe || 'report'}_ev${eventNo}.md`
}
