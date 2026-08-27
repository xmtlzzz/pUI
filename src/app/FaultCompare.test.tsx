// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen, cleanup } from '@testing-library/react'
import type { CompareViewModel } from '../m4/viewModel'
import { FaultCompare } from './FaultCompare'

afterEach(cleanup) // 无 globals 钩子,组件残留会让 getByTestId 跨用例重复命中

/** 手工构造的最小视图模型(不依赖引擎,专注组件行为);结构 = 生产 buildCompareViewModel 输出 */
function makeVm(overrides: Partial<CompareViewModel> = {}): CompareViewModel {
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
      { index: 1, label: '数据段 1 · 100B', kind: 'data', detail: '按序列顺序连续发送' },
      { index: 1, label: 'ACK 前进到 101', kind: 'ack', detail: '每个数据段都被立即确认' },
      { index: 2, label: '数据段 2 · 100B', kind: 'data', detail: '按序列顺序连续发送' },
      { index: 2, label: 'ACK 前进到 201', kind: 'ack', detail: '累计 ACK 单调前进' },
    ],
    degraded: { unorderableInput: false, midStream: false, lengthUnavailable: false, noEvents: false },
    headline: '疑似丢包 / 延迟到达 · 缺口 101–201(100B) · medium',
    ...overrides,
  }
}

describe('FaultCompare 对照页(整页板块)', () => {
  it('阶段卡常驻可见:所有阶段的名称、起止包号、时刻、要点无需交互即可读(审批强化要求)', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const cards = screen.getByTestId('fc-stage-cards')
    for (const label of ['正常传输', '缺口显露', '重复确认与 SACK 增长', '重传回补', '恢复']) {
      expect(cards.textContent).toContain(label)
    }
    expect(cards.textContent).toContain('#6–#6')
    expect(cards.textContent).toContain('#11–#11')
    expect(cards.textContent).toContain('0.030–0.040s')
    expect(cards.textContent).toContain('越过缺口到达')
    // DSH 式总览条存在,阶段段着色
    expect(container.querySelectorAll('.fc-timeband-seg')).toHaveLength(5)
  })

  it('序列空间图形化:刻度/已见条/Gap hatch/SACK/重传回补箭头/ACK 游标全部渲染', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const svg = screen.getByTestId('fc-seqspace')
    // 刻度
    for (const t of [100, 200, 300, 400, 500]) {
      expect(svg.textContent).toContain(String(t))
    }
    // Gap hatch(红色斜纹填充)
    expect(svg.querySelector('rect[fill="url(#fc-hatch)"]')).toBeTruthy()
    // 已见条两段(0-101 / 201-401)
    expect(svg.querySelectorAll('rect[fill="#10b981"]').length).toBe(2)
    // SACK 绿块
    expect(svg.querySelector('rect[fill="#22c55e"]')).toBeTruthy()
    // 重传回补箭头 + ACK 游标
    expect(svg.textContent).toContain('重传回补')
    expect(svg.textContent).toMatch(/ACK/)
    // hatch 覆盖的 tooltip 引用缺口边界
    expect(svg.querySelector('rect[fill="url(#fc-hatch)"]')?.querySelector('title')?.textContent).toContain('101')
    void container
  })

  it('阶段信息面板固定展示当前阶段;点击阶段卡切换(不依赖 hover)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    // 初始:时刻 0 落在首阶段,面板显示阶段 1
    expect(screen.getByTestId('fc-stage-panel').textContent).toContain('阶段 1/5')
    // 点击「重传回补」卡片
    const cards = screen.getAllByRole('button')
    const retxCard = cards.find((b) => b.textContent?.includes('重传回补') && b.className.includes('fc-stage-card'))
    expect(retxCard).toBeTruthy()
    fireEvent.click(retxCard!)
    const panel = screen.getByTestId('fc-stage-panel')
    expect(panel.textContent).toContain('阶段 4/5:重传回补')
    expect(panel.textContent).toContain('#11–#11')
    expect(panel.textContent).toContain('seq=101')
  })

  it('右栏示意基线不含任何真实包号(数据保真红线)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const right = screen.getByLabelText('正常参考示意')
    for (const n of [4, 6, 7, 11, 12]) {
      expect(right.textContent).not.toContain(`#${n}`)
    }
    expect(right.textContent).toContain('示意')
  })

  it('关键报文链 chips:角色标注醒目,点击跳回原报文', () => {
    const onSel = vi.fn()
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={onSel} onBack={vi.fn()} />)
    const chips = screen.getByTestId('fc-messages')
    expect(chips.textContent).toContain('缺口显露')
    expect(chips.textContent).toContain('重传回补')
    expect(chips.textContent).toContain('恢复')
    // 在 chips 容器内定位(阶段卡也含同样文本,避免多重匹配)
    const chip = [...container.querySelectorAll('.fc-keypkt')].find((b) => b.textContent?.includes('#11'))
    expect(chip).toBeTruthy()
    fireEvent.click(chip!)
    expect(onSel).toHaveBeenCalledWith(11)
  })

  it('观察/推断/限制三层固定可见,观察项带跳包按钮', () => {
    const onSel = vi.fn()
    render(<FaultCompare vm={makeVm()} onSelectPacket={onSel} onBack={vi.fn()} />)
    expect(screen.getByText('观察 Observed')).toBeTruthy()
    expect(screen.getByText(/推断 Inference · 置信度 medium/)).toBeTruthy()
    expect(screen.getByText('限制 Limitation')).toBeTruthy()
    expect(screen.getByText('单观察点抓包:无法定位丢包发生在哪个网络节点')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '#6' }))
    expect(onSel).toHaveBeenCalledWith(6)
  })

  it('键盘/静态模式:jsdom 无 matchMedia 时进入静态模式并给出解释;阶段卡照常可点(遍历无动画)', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const wrap = container.querySelector('.fc-page') as HTMLElement
    expect(wrap).toBeTruthy()
    // 静态解释可见(不允许静默失败)
    expect(screen.getByText(/减少动效/)).toBeTruthy()
    // 静态下点击阶段卡 → 面板切换
    const card = screen.getAllByRole('button').find((b) => b.className.includes('fc-stage-card') && b.textContent?.includes('恢复'))
    fireEvent.click(card!)
    expect(screen.getByTestId('fc-stage-panel').textContent).toContain('恢复')
    // Space = 用户显式选择 → 覆盖静态开始播放(解释消失)
    fireEvent.keyDown(wrap, { key: ' ' })
    expect(screen.queryByText(/减少动效/)).toBeNull()
  })

  it('vm=null 时渲染空态并提供返回入口', () => {
    const onBack = vi.fn()
    render(<FaultCompare vm={null} onSelectPacket={vi.fn()} onBack={onBack} />)
    expect(screen.getByTestId('fault-compare-empty').textContent).toContain('未检出可解释的 TCP 事件')
    fireEvent.click(screen.getByText('← 返回时序视图'))
    expect(onBack).toHaveBeenCalledOnce()
  })

  it('降级横幅按需显示', () => {
    const vm = makeVm({ degraded: { unorderableInput: false, midStream: true, lengthUnavailable: true, noEvents: false } })
    render(<FaultCompare vm={vm} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const banner = screen.getByText('⚠ 抓包从连接中途开始:流起始处的缺失不构成丢包证据。').parentElement
    expect(banner?.textContent).toContain('中途开始')
    expect(banner?.textContent).toContain('unknown')
  })
})
