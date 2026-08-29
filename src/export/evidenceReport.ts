import type { CompareViewModel } from '../m4/viewModel'

/**
 * M7 证据化报告 —— 版本化 JSON 证据(schema = pui-evidence / version = evidence-v1)。
 *
 * 与 exportCompareReport(Markdown 证据)同源同构:同一 CompareReportInput 形状
 * (fileName/conversationLabel/eventNo/eventTotal/vm),可选附 M6 的应用层关联(appImpacts)。
 *
 * 口径与红线:
 * - 只导出**实际故障侧**证据;右栏「正常参考」是解释性示意,永不进入证据(有测试钉住);
 * - **确定性**:纯函数,无时间戳/随机数/Date.now,JSON 键序即代码字面量序 ——
 *   同一输入两次 buildEvidenceJson 输出逐字节一致(有测试钉住);
 * - **注入防护**:JSON.stringify 原生转义引号/反斜杠/换行/控制字符,字段值不做改写,
 *   JSON.parse roundtrip 与输入逐字一致;另外把 `<` 统一转成 \u003c(JSON 语义不变),
 *   使原始文本中永不出现 `</script>` 字面量 —— 证据文件即使被粘贴进网页/控制台也不构成注入;
 * - **分层措辞原样透传**:observations/inference/limitations 是引擎分层产物,
 *   导出层绝不改写措辞(与 Markdown 报告同一红线)。
 */

/** 可选的同期应用层关联(M6 AppImpact 的证据侧投影;措辞由 M6 产出,原样透传) */
export interface EvidenceAppImpact {
  /** 应用事件摘要,如 "GET /api/orders 慢响应 2.3s" */
  appSummary: string
  /** 关联的 TCP 事件类型标签(与对照页 kindLabel 同源称谓) */
  tcpKindLabel: string
  /** 完整关联陈述(含「相关/可能影响」级限定措辞,不构成因果) */
  statement: string
}

export interface EvidenceReportInput {
  /** 抓包文件名(溯源) */
  fileName: string
  /** 会话标识 "client ↔ server" */
  conversationLabel: string
  /** 当前导出的事件在切换器中的序号(1 起)与总数 */
  eventNo: number
  eventTotal: number
  vm: CompareViewModel
  /** 可选:同期应用层关联(M6);不传则该节整体省略 */
  appImpacts?: EvidenceAppImpact[]
}

/** 证据文档 JSON 的形状。键序 = buildEvidenceJson 的对象字面量序(确定性契约,勿重排) */
export interface EvidenceJson {
  /** 顶层双键 schema/version 在前:机器可读证据的版本化标识 */
  schema: 'pui-evidence'
  version: 'evidence-v1'
  source: {
    fileName: string
    conversationLabel: string
    eventNo: number
    eventTotal: number
  }
  /** 结论:headline + 事件卡核心字段;gapText 伪重传类(无缺口)省略 */
  conclusion: {
    headline: string
    kindLabel: string
    severity: string
    recovered: boolean
    gapText?: string
  }
  /** 观察(引擎产物,原样透传) */
  observations: Array<{ packetNumber: number; statement: string }>
  /** 推断(引擎产物,原样透传) */
  inference: { statement: string; confidence: string }
  /** 限制(引擎产物,原样透传) */
  limitations: string[]
  /** 故障阶段;index 从 1 起(与 Markdown 报告的 # 序一致) */
  stages: Array<{
    index: number
    label: string
    fromPacket: number
    toPacket: number
    startTime: number
    endTime: number
    summary: string
  }>
  /** 关键报文链(证据链上的报文,非全量报文);roleBadge 缺失时省略 */
  keyPackets: Array<{
    packetNumber: number
    dir: 'c2s' | 's2c'
    label: string
    roleBadge?: string
  }>
  /** 序列空间摘要:viewWindow 为图形视窗取整;gaps 为全量缺口(见下) */
  seqSpace: {
    viewWindow: [number, number]
    gaps: Array<[number, number]>
    /** SACK 块(合并后)数量 —— 已按渲染上限合并/截断后的计数 */
    sackBlocksMergedCount: number
  }
  /** 同期应用层关联;仅调用方传入时存在(不传则该节整体省略) */
  appImpacts?: EvidenceAppImpact[]
  /** 降级说明(视图模型原样,不做布尔重算) */
  degraded: CompareViewModel['degraded']
  /** 固定口径声明(无易变内容) */
  disclaimer: string
}

const EVIDENCE_DISCLAIMER =
  '观察与推断分离;正常参考为解释性示意,不在本证据内;本文件为机器可读证据,与 Markdown 报告同源同口径'

/**
 * 序列化:2 空格缩进(可读、可 diff),再把 `<` 替换为 \u003c。
 * 该替换发生在 stringify 之后,只作用于字符串值内部 —— JSON.parse 结果逐字不变
 * (roundtrip 保持),但原始文本不再含 `</script>` 字面量;替换是确定性的,
 * 不影响逐字节一致性承诺。
 */
function stringifyEvidence(doc: EvidenceJson): string {
  return JSON.stringify(doc, null, 2).replace(/</g, '\\u003c')
}

export function buildEvidenceJson(input: EvidenceReportInput): string {
  const { fileName, conversationLabel, eventNo, eventTotal, vm } = input
  const sq = vm.seqSpace

  const conclusion: EvidenceJson['conclusion'] = {
    headline: vm.headline,
    kindLabel: vm.card.kindLabel,
    severity: vm.card.severity,
    recovered: vm.card.recovered,
  }
  if (vm.card.gapText != null) conclusion.gapText = vm.card.gapText

  // 缺口清单取全量(vm.allGaps):seqSpace.gaps 已按图形视窗裁剪,直接导出会少报
  // 视窗外的缺口 —— 证据宁可列全,不可静默丢弃(与 Markdown 报告同口径);
  // 旧缓存视图模型无 allGaps 时回退 seqSpace.gaps
  const gaps = vm.allGaps ?? sq.gaps

  const doc: EvidenceJson = {
    schema: 'pui-evidence',
    version: 'evidence-v1',
    source: { fileName, conversationLabel, eventNo, eventTotal },
    conclusion,
    observations: vm.card.observations.map((o) => ({ packetNumber: o.packetNumber, statement: o.statement })),
    inference: { statement: vm.card.inference.statement, confidence: vm.card.inference.confidence },
    limitations: [...vm.card.limitations],
    stages: vm.stages.map((s, i) => ({
      index: i + 1,
      label: s.label,
      fromPacket: s.fromPacket,
      toPacket: s.toPacket,
      startTime: s.startTime,
      endTime: s.endTime,
      summary: s.summary,
    })),
    keyPackets: vm.keyPackets.map((k) => {
      const kp: EvidenceJson['keyPackets'][number] = { packetNumber: k.packetNumber, dir: k.dir, label: k.label }
      if (k.roleBadge != null) kp.roleBadge = k.roleBadge
      return kp
    }),
    seqSpace: {
      viewWindow: [Math.round(sq.axisMin), Math.round(sq.axisMax)],
      gaps: gaps.map((g) => [g[0], g[1]] as [number, number]),
      sackBlocksMergedCount: sq.sackBlocks.length,
    },
    // 条件展开保持键序:appImpacts 恰在 seqSpace 与 degraded 之间(规格键序)
    ...(input.appImpacts
      ? {
          appImpacts: input.appImpacts.map((a) => ({
            appSummary: a.appSummary,
            tcpKindLabel: a.tcpKindLabel,
            statement: a.statement,
          })),
        }
      : {}),
    degraded: { ...vm.degraded },
    disclaimer: EVIDENCE_DISCLAIMER,
  }
  return stringifyEvidence(doc)
}

/** 导出文件名:与 defaultCompareReportName 同风格(evidence_<safe>_ev<N>.json) */
export function defaultEvidenceJsonName(conversationLabel: string, eventNo: number): string {
  const safe = conversationLabel.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
  return `evidence_${safe || 'evidence'}_ev${eventNo}.json`
}
