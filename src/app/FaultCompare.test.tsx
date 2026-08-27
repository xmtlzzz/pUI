// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen, cleanup } from '@testing-library/react'
import type { CompareEventSummary, CompareViewModel } from '../m4/viewModel'
import { FaultCompare, SeqSpaceGraphic } from './FaultCompare'

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
    marks: { gapRevealAt: 0.12, dupAckWindow: [0.2, 0.5], retxDrawAt: 0.55, recoverAt: 0.9 },
    direction: 'c2s',
    opposite: null,
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
    expect(onSel).toHaveBeenCalledWith(11, { eventIndex: 0, stageIndex: 0 })
  })

  it('观察/推断/限制三层固定可见,观察项带跳包按钮(携带事件+阶段上下文)', () => {
    const onSel = vi.fn()
    render(<FaultCompare vm={makeVm()} onSelectPacket={onSel} eventIndex={2} onBack={vi.fn()} />)
    expect(screen.getByText('观察 Observed')).toBeTruthy()
    expect(screen.getByText(/推断 Inference · 置信度 medium/)).toBeTruthy()
    expect(screen.getByText('限制 Limitation')).toBeTruthy()
    expect(screen.getByText('单观察点抓包:无法定位丢包发生在哪个网络节点')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '#6' }))
    // 上下文按分镜粒度:当前事件下标 + 初始活动阶段(时刻 0 → 阶段 0)
    expect(onSel).toHaveBeenCalledWith(6, { eventIndex: 2, stageIndex: 0 })
  })

  it('选中阶段后跳包:ctx.stageIndex 为所选阶段;initialStageIndex 挂载时恢复到该阶段起点', () => {
    const onSel = vi.fn()
    const view = render(<FaultCompare vm={makeVm()} onSelectPacket={onSel} onBack={vi.fn()} />)
    const retxCard = screen.getAllByRole('button').find(
      (b) => b.className.includes('fc-stage-card') && b.textContent?.includes('重传回补'),
    )!
    fireEvent.click(retxCard)
    const chip = [...view.container.querySelectorAll('.fc-keypkt')].find((b) => b.textContent?.includes('#11'))!
    fireEvent.click(chip)
    expect(onSel).toHaveBeenCalledWith(11, { eventIndex: 0, stageIndex: 3 })

    // 恢复挂载:initialStageIndex=3 → 播放游标位于该阶段起点(t0>0),面板直接显示阶段 4
    view.unmount()
    const restored = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} initialStageIndex={3} onBack={vi.fn()} />)
    expect(screen.getByTestId('fc-stage-panel').textContent).toContain('阶段 4/5')
    const cursor = restored.container.querySelector('.fc-timeband-cursor') as HTMLElement | null
    expect(cursor).toBeTruthy()
    expect(Number.parseFloat(cursor!.style.left)).toBeGreaterThan(0) // 不再是起点 0
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

  it('阶段带内嵌阶段名标注(常驻,非 hover):宽段显示「序号. 阶段名」,窄段退化为序号', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const tags = [...container.querySelectorAll('.fc-seg-tag')]
    expect(tags.length).toBe(5) // makeVm 五个阶段宽度均 ≥3%,全部有标注
    // 宽段(0.34)带阶段名;窄段(0.08)只带序号
    expect(tags.map((t) => t.textContent)).toContain('3. 重复确认与 SACK 增长')
    expect(tags.some((t) => t.textContent === '2')).toBe(true)
  })

  it('序列空间图例与轴说明:红绿块含义显式可读(用户反馈)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const legend = screen.getByTestId('fc-seq-legend')
    expect(legend.textContent).toContain('已见字节')
    expect(legend.textContent).toContain('缺口')
    expect(legend.textContent).toContain('SACK')
    expect(legend.textContent).toContain('重传回补')
    // 轴说明:这是字节序列号空间
    const svg = screen.getByTestId('fc-seqspace')
    expect(svg.textContent).toContain('序列号空间(字节)')
  })

  it('对向序列空间:双向流出现方向切换(.seg),切换后渲染对向静态视图', () => {
    const vm = makeVm({
      direction: 'c2s',
      opposite: {
        dir: 's2c',
        view: {
          axisMin: 0,
          axisMax: 201,
          ticks: [50, 100, 150, 200],
          seenRuns: [[1, 201]],
          gaps: [],
          sackBlocks: [],
          ackTrack: [{ time: 0.28, ack: 201 }],
          retxArrow: undefined,
        },
      },
    })
    const view = render(<FaultCompare vm={vm} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    // 切换器出现(主界面 .seg 风格)
    const toggle = screen.getByTestId('fc-dir-toggle')
    expect(toggle.textContent).toContain('事件方向(c2s)')
    expect(toggle.textContent).toContain('对向(s2c)')
    // 默认事件方向视图
    expect(screen.getByLabelText('序列空间图形化')).toBeTruthy()
    // 切到对向 → 对向静态视图(独立 aria-label,轴覆盖对向数据)
    fireEvent.click(toggle.querySelectorAll('button')[1])
    const opp = screen.getByLabelText('对向序列空间')
    expect(opp.textContent).toContain('对向全景') // 轴说明切换为对向全景
    expect(opp.textContent).toMatch(/150/) // 对向刻度
    // 切回事件方向
    fireEvent.click(toggle.querySelectorAll('button')[0])
    expect(screen.getByLabelText('序列空间图形化')).toBeTruthy()
    void view
  })

  it('窄窗口(<900px):双标签切换实际故障/正常参考,单栏渲染', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
    }))
    const view = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    // 双标签出现,默认实际故障;正常参考栏不渲染
    const tabs = screen.getByTestId('fc-tabs')
    expect(tabs.textContent).toContain('实际故障')
    expect(tabs.textContent).toContain('正常参考')
    expect(screen.queryByLabelText('正常参考示意')).toBeNull()
    expect(screen.getByLabelText('实际故障')).toBeTruthy()
    // 切到正常参考 → 实际故障让位
    fireEvent.click(tabs.querySelectorAll('button')[1])
    expect(screen.queryByLabelText('实际故障')).toBeNull()
    expect(screen.getByLabelText('正常参考示意')).toBeTruthy()
    vi.unstubAllGlobals()
    view.unmount()
  })

  it('vm=null 时渲染空态并提供返回入口', () => {
    const onBack = vi.fn()
    render(<FaultCompare vm={null} onSelectPacket={vi.fn()} onBack={onBack} />)
    expect(screen.getByTestId('fault-compare-empty').textContent).toContain('未检出可解释的 TCP 事件')
    fireEvent.click(screen.getByText('← 返回时序视图'))
    expect(onBack).toHaveBeenCalledOnce()
  })

  it('静态模式(reduced-motion):分镜元素不经动画直接完整呈现,信息与终态等价', () => {
    // jsdom 无 matchMedia → usePlayback 恒为 static → progressive=false
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const svg = screen.getByTestId('fc-seqspace')
    const gap = svg.querySelector('[data-testid="fc-gap-0"]')!
    expect(gap.getAttribute('opacity')).toBe('1') // Gap 无淡入直接可见
    expect(gap.getAttribute('width')).not.toBe('0')
    // SACK 完整宽度(无增长裁剪)
    const sack = svg.querySelector('rect[fill="#22c55e"]') as SVGRectElement | null
    expect(sack).toBeTruthy()
    expect(Number(sack!.getAttribute('opacity'))).toBe(1)
    // 重传箭头完整画出(y2 顶到 46)
    const retxLine = [...svg.querySelectorAll('line')].find((l) => l.getAttribute('stroke') === '#ef4444')!
    expect(retxLine.getAttribute('y2')).toBe('46')
    // ACK 游标存在
    expect(svg.textContent).toMatch(/ACK \d/)
  })

  it('progressive 播放态下元素按登场时刻显隐(GSAP 只补间时间,元素状态声明式)', () => {
    // progressive=true 时,时刻 0 尚未到 gapRevealAt:Gap 应不可见(opacity=0)
    const vm = makeVm({ marks: { gapRevealAt: 0.12, dupAckWindow: [0.2, 0.5], retxDrawAt: 0.55, recoverAt: 0.9 } })
    const view = render(<SeqSpaceGraphic vm={vm} playhead={0} progressive />)
    let gap = view.container.querySelector('[data-testid="fc-gap-0"]')!
    expect(gap.getAttribute('opacity')).toBe('0')
    // 越过登场时刻后完全可见
    const mid = render(<SeqSpaceGraphic vm={vm} playhead={0.5} progressive />)
    gap = mid.container.querySelector('[data-testid="fc-gap-0"]')!
    expect(Number(gap.getAttribute('opacity'))).toBeCloseTo(1, 1)
    // SACK 在窗口中点应有部分进度、窗口后满宽
    const sackAtMid = Number(
      render(<SeqSpaceGraphic vm={vm} playhead={0.35} progressive />).container.querySelector('rect[fill="#22c55e"]')?.getAttribute('width'),
    )
    const sackAtEnd = Number(mid.container.querySelector('rect[fill="#22c55e"]')?.getAttribute('width'))
    expect(sackAtMid).toBeGreaterThan(0)
    expect(sackAtMid).toBeLessThan(sackAtEnd)
    // 恢复脉冲在 recoverAt 后出现(「缺口闭合」提示),脉冲窗与终态都消失
    expect(mid.container.textContent).not.toContain('缺口闭合') // t=0.5 早于 recoverAt=0.9
    cleanup()
    const duringPing = render(<SeqSpaceGraphic vm={vm} playhead={0.93} progressive />)
    expect(duringPing.container.textContent).toContain('缺口闭合')
    const after = render(<SeqSpaceGraphic vm={vm} playhead={0.99} progressive />)
    expect(after.container.textContent).not.toContain('缺口闭合')
    // 但 ACK 游标在终态仍然驻留(信息不随动画消失)
    expect(after.container.textContent).toMatch(/ACK \d/)
  })

  it('降级横幅按需显示', () => {
    const vm = makeVm({ degraded: { unorderableInput: false, midStream: true, lengthUnavailable: true, noEvents: false } })
    render(<FaultCompare vm={vm} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const banner = screen.getByText('⚠ 抓包从连接中途开始:流起始处的缺失不构成丢包证据。').parentElement
    expect(banner?.textContent).toContain('中途开始')
    expect(banner?.textContent).toContain('unknown')
  })
})

describe('FaultCompare 多事件切换器(VDI 实测:单会话大量缺口事件)', () => {
  const summaries: CompareEventSummary[] = [
    {
      id: '0:c2s:possible-loss-or-delay:101',
      kindLabel: '疑似丢包 / 延迟到达',
      severity: 'high',
      recovered: false,
      gapText: '101–201(100B)',
      startTime: 0.05,
      endTime: 0.26,
    },
    {
      id: '0:c2s:possible-ack-loss-or-spurious:201',
      kindLabel: '疑似 ACK 丢失 / 冗余重传',
      severity: 'low',
      recovered: true,
      gapText: undefined,
      startTime: 0.3,
      endTime: 0.31,
    },
    {
      id: '0:c2s:reordering:301',
      kindLabel: '乱序到达',
      severity: 'low',
      recovered: true,
      gapText: '301–401(100B)',
      startTime: 0.4,
      endTime: 0.42,
    },
  ]

  it('左栏顶部渲染事件列表:序号/类型/缺口/未恢复标注齐备,当前项高亮', () => {
    const { container } = render(
      <FaultCompare vm={makeVm()} events={summaries} eventIndex={1} onSelectEvent={vi.fn()} onSelectPacket={vi.fn()} onBack={vi.fn()} />,
    )
    const list = screen.getByTestId('fc-event-list')
    // 三条事件的类型标签齐全(引擎优先序展示)
    expect(list.textContent).toContain('疑似丢包 / 延迟到达')
    expect(list.textContent).toContain('疑似 ACK 丢失 / 冗余重传')
    expect(list.textContent).toContain('乱序到达')
    // 未恢复徽标只标在未恢复事件上
    expect(list.querySelectorAll('.fc-evbtn-unrec')).toHaveLength(1)
    expect(list.textContent).toContain('未恢复')
    // 当前选中是第 2 个
    const tabs = [...container.querySelectorAll('.fc-evbtn')]
    expect(tabs).toHaveLength(3)
    expect(tabs[1].className).toContain('active')
    expect(tabs[1].getAttribute('aria-selected')).toBe('true')
  })

  it('点击条目触发 onSelectEvent(下标);事件卡仍由当前 vm 渲染', () => {
    const onSel = vi.fn()
    render(<FaultCompare vm={makeVm()} events={summaries} eventIndex={0} onSelectEvent={onSel} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const tabs = screen.getAllByRole('tab')
    fireEvent.click(tabs[2])
    expect(onSel).toHaveBeenCalledWith(2)
    // 当前事件的完整信息不受列表影响
    expect(screen.getByTestId('fc-stage-panel')).toBeTruthy()
  })

  it('不传 events 或只有一个事件时不渲染切换器(向后兼容)', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    expect(container.querySelector('[data-testid="fc-event-list"]')).toBeNull()
    const single = render(<FaultCompare vm={makeVm()} events={[summaries[0]]} eventIndex={0} onSelectEvent={vi.fn()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    expect(single.container.querySelector('[data-testid="fc-event-list"]')).not.toBeNull()
  })

  it('eventKey 变化重挂载内容区:阶段选中与播放进度复位到初始态', () => {
    const props = {
      vm: makeVm(),
      events: summaries,
      eventIndex: 0,
      onSelectEvent: vi.fn(),
      onSelectPacket: vi.fn(),
      onBack: vi.fn(),
    }
    const view = render(<FaultCompare {...props} eventKey={summaries[0].id} />)

    // 选中的是阶段带上的「重传回补」卡(第 4 阶段)
    const retxCard = screen.getAllByRole('button').find(
      (b) => b.className.includes('fc-stage-card') && b.textContent?.includes('重传回补'),
    )!
    fireEvent.click(retxCard)
    expect(screen.getByTestId('fc-stage-panel').textContent).toContain('阶段 4/5')

    // 切换事件(父层换 key 重挂载):选中态必须归零回到首阶段,不得把上个事件的浏览位置带过去
    view.rerender(<FaultCompare {...props} eventKey={summaries[2].id} />)
    expect(screen.getByTestId('fc-stage-panel').textContent).toContain('阶段 1/5')
    expect(view.container.querySelector('.fc-timeband-seg.active')).toBeTruthy() // 首阶段高亮
  })
})
