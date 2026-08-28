import { describe, expect, it } from 'vitest'
import type { CompareViewModel } from '../m4/viewModel'
import { defaultCompareReportName, exportCompareReport } from './exportCompareReport'

/** 与 FaultCompare.test.tsx 同构的最小 vm(不重复引擎路径;结构 = 生产输出) */
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
      { packetNumber: 11, time: 0.25, dir: 'c2s', label: 'PSH·ACK seq=101 len=100', stageIndex: 3, roleBadge: '重传回补' },
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
    degraded: { unorderableInput: false, midStream: true, lengthUnavailable: false, noEvents: false },
    headline: '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium',
  }
}

describe('exportCompareReport — 对照页证据导出', () => {
  const input = {
    fileName: 'VDI_202608.pcapng',
    conversationLabel: '10.0.0.1:1234 ↔ 93.184.216.34:443',
    eventNo: 2,
    eventTotal: 5,
    vm: makeVm(),
  }

  it('包含证据要素:标题/事件序号/缺口/观察表/推断/限制/阶段表/关键报文链', () => {
    const md = exportCompareReport(input)
    expect(md).toContain('# 故障分析报告 · 事件 2/5')
    expect(md).toContain('VDI_202608.pcapng')
    expect(md).toContain('101–201')
    expect(md).toContain('### 观察 Observed')
    expect(md).toContain('| 6 | #6 |')
    expect(md).toMatch(/推断 Inference.*置信度 medium/)
    expect(md).toContain('- 单观察点抓包')
    expect(md).toContain('## 故障阶段')
    expect(md).toContain('正常传输')
    expect(md).toContain('## 关键报文链')
    expect(md).toContain('缺口显露')
    // 降级说明随事件导出
    expect(md).toContain('中途开始')
  })

  it('数据保真红线:正常参考侧的步骤内容不出现在导出中(口径说明除外)', () => {
    const md = exportCompareReport(input)
    // 示意步骤的措辞与序号体系不得混入
    expect(md).not.toContain('数据段 1')
    expect(md).not.toContain('按序列顺序连续发送')
    // 明确注明导出口径(尾注提及"正常参考"是说明其不在报告内,允许)
    expect(md).toContain('正常参考为解释性示意,不在本报告内')
  })

  it('Markdown 注入防护:报文标签/文案中的反引号/竖线/尖括号被转义', () => {
    const vm = makeVm()
    vm.keyPackets = [
      { packetNumber: 6, time: 0.05, dir: 'c2s', label: 'PSH·ACK `seq=201` | <img onerror>', stageIndex: 1, roleBadge: '缺`口`' },
    ]
    const md = exportCompareReport({ ...input, vm })
    // 表格单元格内:反引号/竖线被前置反斜杠转义,尖括号整体剥除(防 <img onerror> 透传)
    expect(md).toContain('| 6 | → | `PSH·ACK \\`seq=201\\` \\| img onerror` |')
    expect(md).not.toContain('<img')
  })

  it('未恢复事件标注加粗;伪重传(无缺口)显示"无"', () => {
    const vm = makeVm()
    vm.card.recovered = false
    vm.card.gapText = undefined
    vm.seqSpace.gaps = []
    const md = exportCompareReport({ ...input, vm })
    expect(md).toContain('**未恢复**')
    expect(md).toContain('- 缺口: 无(伪重传/窗口类场景)')
  })

  it('文件名 ASCII 安全且含事件序号', () => {
    expect(defaultCompareReportName('10.0.0.1:1234 ↔ 93.184.216.34:443', 3)).toMatch(/^fault_[\w.-]+_ev3\.md$/)
    expect(defaultCompareReportName('中文会话 <>:1', 1)).not.toMatch(/[\u4e00-\u9fff<>]/)
  })
})
