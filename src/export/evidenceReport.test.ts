import { describe, expect, it } from 'vitest'
import type { CompareViewModel } from '../m4/viewModel'
import { buildEvidenceJson, defaultEvidenceJsonName, type EvidenceJson } from './evidenceReport'

/** 与 FaultCompare.test.tsx 同构的最小 vm(不重复引擎路径;结构 = 生产输出,字段最全) */
function makeVm(): CompareViewModel {
  return {
    card: {
      kindLabel: '疑似丢包 / 延迟到达',
      severity: 'medium',
      recovered: true,
      gapText: '101–201(100B)',
      observations: [
        { packetNumber: 6, statement: '序列空间存在缺口 101–201(100 字节),由该报文越过缺口到达而暴露' },
        { packetNumber: 11, statement: '缺失数据被重新发送' },
      ],
      inference: { statement: '观察到数据未按连续序列到达,随后由重传补齐;不能据此断定丢包位置', confidence: 'medium' },
      limitations: ['单观察点抓包:无法定位丢包发生在哪个网络节点', '无法排除抓包点自身漏包(网卡/ring buffer/镜像口)'],
    },
    seqSpace: {
      axisMin: 0,
      axisMax: 501,
      ticks: [100, 200, 300, 400, 500],
      seenRuns: [
        [0, 101],
        [201, 401],
      ],
      gaps: [[101, 201]],
      sackBlocks: [[201, 501]],
      ackTrack: [
        { time: 0.04, ack: 101 },
        { time: 0.26, ack: 501 },
      ],
      retxArrow: { seq: 101 },
      rangeLabels: [
        { start: 0, end: 101, text: '数据', kind: 'seen' },
        { start: 201, end: 401, text: '数据', kind: 'seen' },
        { start: 101, end: 201, text: '未收到', kind: 'gap' },
      ],
    },
    keyPackets: [
      { packetNumber: 6, time: 0.05, dir: 'c2s', label: 'PSH·ACK seq=201 len=100', stageIndex: 1, roleBadge: '缺口显露' },
      { packetNumber: 7, time: 0.06, dir: 's2c', label: 'ACK ack=101', stageIndex: 2, roleBadge: '重复确认 ×3' },
      { packetNumber: 11, time: 0.25, dir: 'c2s', label: 'PSH·ACK seq=101 len=100', stageIndex: 3, roleBadge: '重传回补' },
      { packetNumber: 12, time: 0.26, dir: 's2c', label: 'ACK ack=501', stageIndex: 4, roleBadge: '恢复' },
    ],
    stages: [
      { label: '正常传输', summary: '段 #4 被正常确认,序列空间无缺口', fromPacket: 4, toPacket: 5, startTime: 0.03, endTime: 0.04, observationRefs: [], t0: 0, t1: 0.08 },
      { label: '缺口显露', summary: '#6 越过缺口到达,出现缺口 101–201', fromPacket: 6, toPacket: 6, startTime: 0.05, endTime: 0.05, observationRefs: ['o1'], t0: 0.08, t1: 0.16 },
      { label: '重复确认与 SACK 增长', summary: 'ACK 停在 101 未前进(3 次);SACK 报告缺口后数据已到达', fromPacket: 7, toPacket: 11, startTime: 0.06, endTime: 0.09, observationRefs: ['o2'], t0: 0.16, t1: 0.5 },
      { label: '重传回补', summary: '#11 重发缺失数据(seq=101),几何上精确回补缺口', fromPacket: 11, toPacket: 11, startTime: 0.25, endTime: 0.25, observationRefs: ['o3'], t0: 0.5, t1: 0.9 },
      { label: '恢复', summary: '#12 ACK 前进到 501,缺口闭合', fromPacket: 12, toPacket: 12, startTime: 0.26, endTime: 0.26, observationRefs: ['o4'], t0: 0.9, t1: 1 },
    ],
    referenceSteps: [
      // 红线样本:右栏示意步骤,绝不能出现在证据里
      { index: 1, label: '数据段 1 · 100B', kind: 'data', detail: '按序列顺序连续发送' },
      { index: 1, label: 'ACK 前进到 101', kind: 'ack', detail: '每个数据段都被立即确认' },
    ],
    marks: { gapRevealAt: 0.12, dupAckWindow: [0.2, 0.5], retxDrawAt: 0.55, recoverAt: 0.9 },
    direction: 'c2s',
    opposite: null,
    panorama: null,
    // 全量缺口(未按图形视窗裁剪)—— 证据按它列全,不缺报
    allGaps: [[101, 201]],
    eventPins: [
      { packetNumber: 6, seq: 201, label: '#6 缺口显露', colorIndex: 1, kind: 'data', len: 100 },
      { packetNumber: 11, seq: 101, label: '#11 重传回补', colorIndex: 3, kind: 'data', len: 100 },
    ],
    degraded: { unorderableInput: false, midStream: true, lengthUnavailable: false, noEvents: false },
    headline: '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium',
  }
}

describe('buildEvidenceJson — 版本化 JSON 证据导出', () => {
  const input = {
    fileName: 'VDI_202608.pcapng',
    conversationLabel: '10.0.0.1:1234 ↔ 93.184.216.34:443',
    eventNo: 2,
    eventTotal: 5,
    vm: makeVm(),
  }

  it('顶层双键 schema/version 在前;键序即代码字面量序(确定性契约)', () => {
    const parsed = JSON.parse(buildEvidenceJson(input)) as EvidenceJson
    expect(Object.keys(parsed)).toEqual([
      'schema',
      'version',
      'source',
      'conclusion',
      'observations',
      'inference',
      'limitations',
      'stages',
      'keyPackets',
      'seqSpace',
      'degraded',
      'disclaimer',
    ])
    expect(parsed.schema).toBe('pui-evidence')
    expect(parsed.version).toBe('evidence-v1')
    expect(Object.keys(parsed.source)).toEqual(['fileName', 'conversationLabel', 'eventNo', 'eventTotal'])
    expect(Object.keys(parsed.conclusion)).toEqual(['headline', 'kindLabel', 'severity', 'recovered', 'gapText'])
  })

  it('证据要素齐全:source/结论/观察/推断/限制/阶段/关键报文/序列空间摘要', () => {
    const parsed = JSON.parse(buildEvidenceJson(input)) as EvidenceJson
    expect(parsed.source).toEqual({
      fileName: 'VDI_202608.pcapng',
      conversationLabel: '10.0.0.1:1234 ↔ 93.184.216.34:443',
      eventNo: 2,
      eventTotal: 5,
    })
    expect(parsed.conclusion).toEqual({
      headline: '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium',
      kindLabel: '疑似丢包 / 延迟到达',
      severity: 'medium',
      recovered: true,
      gapText: '101–201(100B)',
    })
    expect(parsed.seqSpace.viewWindow).toEqual([0, 501])
    expect(parsed.seqSpace.sackBlocksMergedCount).toBe(1)
    expect(parsed.stages.map((s) => s.index)).toEqual([1, 2, 3, 4, 5])
    // 阶段不含视图模型的归一化坐标(t0/t1),index 从 1 起
    expect(parsed.stages[1]).toEqual({
      index: 2,
      label: '缺口显露',
      fromPacket: 6,
      toPacket: 6,
      startTime: 0.05,
      endTime: 0.05,
      summary: '#6 越过缺口到达,出现缺口 101–201',
    })
    expect(parsed.keyPackets[0]).toEqual({
      packetNumber: 6,
      dir: 'c2s',
      label: 'PSH·ACK seq=201 len=100',
      roleBadge: '缺口显露',
    })
  })

  it('分层措辞原样透传:观察/推断/限制是引擎产物,导出层逐字不改写', () => {
    const parsed = JSON.parse(buildEvidenceJson(input)) as EvidenceJson
    expect(parsed.observations).toEqual(input.vm.card.observations)
    expect(parsed.inference).toEqual(input.vm.card.inference)
    expect(parsed.limitations).toEqual(input.vm.card.limitations)
    // disclaimer 固定口径:观察与推断分离、正常参考不在证据内、与 Markdown 同源
    expect(parsed.disclaimer).toContain('观察与推断分离')
    expect(parsed.disclaimer).toContain('正常参考为解释性示意,不在本证据内')
    expect(parsed.disclaimer).toContain('与 Markdown 报告同源同口径')
  })

  it('确定性:同一输入两次构建逐字节一致;无时间戳/随机数等易变字段', () => {
    const a = buildEvidenceJson(input)
    const b = buildEvidenceJson(input)
    expect(a).toBe(b)
    // 结构上保证:任何形如"导出时刻/随机 id"的字段都不允许出现
    expect(a).not.toMatch(/generatedAt|exportedAt|"timestamp"|random/i)
  })

  it('数据保真红线:正常参考侧示意绝不进入证据(口径声明除外)', () => {
    const json = buildEvidenceJson(input)
    // 示意步骤的措辞与序号体系不得混入
    // (阶段 summary 里合法出现的"ACK 前进到 501"不在此列 —— 只钉示意步骤专属措辞)
    expect(json).not.toContain('数据段 1')
    expect(json).not.toContain('按序列顺序连续发送')
    expect(json).not.toContain('每个数据段都被立即确认')
    // disclaimer 提及"正常参考"是声明其不在证据内,允许
    expect(json).toContain('正常参考为解释性示意,不在本证据内')
  })

  it('注入防护:JSON.stringify 原生转义,JSON.parse 可解析且字段值 roundtrip 逐字一致', () => {
    const vm = makeVm()
    const evilLabel = 'PSH·ACK `seq=201` "quoted" </script><script>alert(1)</script>\n第二行'
    vm.keyPackets = [{ packetNumber: 6, time: 0.05, dir: 'c2s', label: evilLabel, stageIndex: 1, roleBadge: '缺口显露' }]
    const evil = {
      ...input,
      conversationLabel: '10.0.0.1:1 ↔ `evil` "</script>\n→',
      vm,
    }
    // parse 不抛错即为可解析;字段值与输入逐字一致(roundtrip)
    const parsed = JSON.parse(buildEvidenceJson(evil)) as EvidenceJson
    expect(parsed.source.conversationLabel).toBe(evil.conversationLabel)
    expect(parsed.keyPackets[0].label).toBe(evilLabel)
    expect(parsed.keyPackets[0].roleBadge).toBe('缺口显露')
    // 原始文本不含 </script> 字面量(< 已统一转义为 \u003c,嵌入网页/控制台亦安全)
    expect(buildEvidenceJson(evil)).not.toContain('</script>')
    expect(buildEvidenceJson(evil)).toContain('\\u003c/script>')
  })

  it('gapText 可选:伪重传(无缺口)时 conclusion 省略 gapText 键', () => {
    const vm = makeVm()
    vm.card.gapText = undefined
    vm.card.recovered = false
    const parsed = JSON.parse(buildEvidenceJson({ ...input, vm })) as EvidenceJson
    expect(Object.keys(parsed.conclusion)).toEqual(['headline', 'kindLabel', 'severity', 'recovered'])
    expect(parsed.conclusion.recovered).toBe(false)
  })

  it('缺口清单取全量 allGaps(视窗外不少报);老缓存缺 allGaps 时回退 seqSpace.gaps', () => {
    const vm = makeVm()
    // 图形视窗只覆盖到 501;视窗外还有一个 1500–1601 的缺口
    vm.seqSpace.gaps = [[101, 201]]
    vm.allGaps = [
      [101, 201],
      [1500, 1601],
    ]
    const parsed = JSON.parse(buildEvidenceJson({ ...input, vm })) as EvidenceJson
    expect(parsed.seqSpace.gaps).toEqual([
      [101, 201],
      [1500, 1601],
    ])

    // 老缓存视图模型(无 allGaps 字段)兜底:回退 seqSpace.gaps,不抛错不缺节
    const legacy = { ...makeVm() } as Partial<CompareViewModel>
    delete legacy.allGaps
    const parsedLegacy = JSON.parse(buildEvidenceJson({ ...input, vm: legacy as CompareViewModel })) as EvidenceJson
    expect(parsedLegacy.seqSpace.gaps).toEqual([[101, 201]])
  })

  it('viewWindow 为图形视窗取整(axisMin/axisMax 四舍五入)', () => {
    const vm = makeVm()
    vm.seqSpace.axisMin = 0.4
    vm.seqSpace.axisMax = 500.6
    const parsed = JSON.parse(buildEvidenceJson({ ...input, vm })) as EvidenceJson
    expect(parsed.seqSpace.viewWindow).toEqual([0, 501])
  })

  it('appImpacts:传入时逐字透传(限定措辞不改写)且键序居中;不传时整节省略', () => {
    const appImpacts = [
      {
        appSummary: 'GET /api/orders 慢响应 2.3s',
        tcpKindLabel: '疑似丢包 / 延迟到达',
        statement: '「GET /api/orders 慢响应 2.3s」与 疑似丢包 / 延迟到达 时间窗重叠(±2s):同期现象,可能相关,不构成因果',
      },
    ]
    const withSection = JSON.parse(buildEvidenceJson({ ...input, appImpacts })) as EvidenceJson
    expect(withSection.appImpacts).toEqual(appImpacts)
    // 键序:appImpacts 恰在 seqSpace 与 degraded 之间(规格键序)
    expect(Object.keys(withSection)).toEqual([
      'schema',
      'version',
      'source',
      'conclusion',
      'observations',
      'inference',
      'limitations',
      'stages',
      'keyPackets',
      'seqSpace',
      'appImpacts',
      'degraded',
      'disclaimer',
    ])

    const without = JSON.parse(buildEvidenceJson(input)) as EvidenceJson
    expect('appImpacts' in without).toBe(false)
  })

  it('roleBadge 可选:无角色徽标的关键报文省略该键', () => {
    const vm = makeVm()
    vm.keyPackets = [
      vm.keyPackets[0],
      { packetNumber: 12, time: 0.26, dir: 's2c', label: 'ACK ack=501', stageIndex: 4 },
    ]
    const parsed = JSON.parse(buildEvidenceJson({ ...input, vm })) as EvidenceJson
    expect(Object.keys(parsed.keyPackets[0])).toEqual(['packetNumber', 'dir', 'label', 'roleBadge'])
    expect(Object.keys(parsed.keyPackets[1])).toEqual(['packetNumber', 'dir', 'label'])
  })

  it('degraded 原样透传(不做布尔重算)', () => {
    const parsed = JSON.parse(buildEvidenceJson(input)) as EvidenceJson
    expect(parsed.degraded).toEqual(input.vm.degraded)
    expect(parsed.degraded.midStream).toBe(true)
  })

  it('defaultEvidenceJsonName:ASCII 安全、含事件序号,风格对齐 Markdown 导出', () => {
    expect(defaultEvidenceJsonName('10.0.0.1:1234 ↔ 93.184.216.34:443', 3)).toMatch(/^evidence_[\w.-]+_ev3\.json$/)
    expect(defaultEvidenceJsonName('中文会话 <>:1', 1)).not.toMatch(/[\u4e00-\u9fff<>]/)
    // 清洗后为空时回退占位名,保证文件名永远合法
    expect(defaultEvidenceJsonName('', 1)).toBe('evidence_evidence_ev1.json')
  })
})
