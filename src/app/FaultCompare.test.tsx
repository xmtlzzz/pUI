// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen, cleanup } from '@testing-library/react'
import type { CompareViewModel } from '../m4/viewModel'
import { FaultCompare } from './FaultCompare'

afterEach(cleanup) // 无 globals 钩子,组件残留会让 getByTestId 跨用例重复命中

/** 手工构造的最小视图模型(不依赖引擎,专注组件行为) */
function makeVm(overrides: Partial<CompareViewModel> = {}): CompareViewModel {
  return {
    leftMessages: [
      { packetNumber: 4, time: 0.03, dir: 'c2s', label: 'PSH·ACK seq=1 len=100', stageIndex: 0 },
      { packetNumber: 6, time: 0.05, dir: 'c2s', label: 'PSH·ACK seq=201 len=100', stageIndex: 1, roleBadge: '缺口显露' },
      { packetNumber: 7, time: 0.06, dir: 's2c', label: 'ACK seq=1 ack=101', stageIndex: 2, roleBadge: '重复确认 ×3' },
      { packetNumber: 12, time: 0.25, dir: 'c2s', label: 'PSH·ACK seq=101 len=100', stageIndex: 3, roleBadge: '重传回补' },
      { packetNumber: 13, time: 0.26, dir: 's2c', label: 'ACK seq=1 ack=501', stageIndex: 4, roleBadge: '恢复' },
    ],
    stages: [
      { label: '正常传输', summary: '段 #4 被正常确认,序列空间无缺口', fromPacket: 4, toPacket: 5, startTime: 0.03, endTime: 0.04, observationRefs: [], t0: 0, t1: 0.08 },
      { label: '缺口显露', summary: '#6 越过缺口到达,出现缺口 101–201', fromPacket: 6, toPacket: 6, startTime: 0.05, endTime: 0.05, observationRefs: ['o1'], t0: 0.08, t1: 0.16 },
      { label: '重复确认与 SACK 增长', summary: 'ACK 停在 101 未前进(3 次);SACK 报告缺口后数据已到达', fromPacket: 7, toPacket: 11, startTime: 0.06, endTime: 0.09, observationRefs: ['o2'], t0: 0.16, t1: 0.5 },
      { label: '重传回补', summary: '#12 重发缺失数据(seq=101)', fromPacket: 12, toPacket: 12, startTime: 0.25, endTime: 0.25, observationRefs: ['o3'], t0: 0.5, t1: 0.9 },
      { label: '恢复', summary: '#13 ACK 前进到 501,缺口闭合', fromPacket: 13, toPacket: 13, startTime: 0.26, endTime: 0.26, observationRefs: ['o4'], t0: 0.9, t1: 1 },
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

describe('FaultCompare 对照页', () => {
  it('阶段带常驻可见:所有阶段的名称、起止包号、要点无需任何交互即可读(审批强化要求)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const band = screen.getByTestId('fc-stageband')
    for (const label of ['正常传输', '缺口显露', '重复确认与 SACK 增长', '重传回补', '恢复']) {
      expect(band.textContent).toContain(label)
    }
    expect(band.textContent).toContain('#6–#6')
    expect(band.textContent).toContain('越过缺口到达')
  })

  it('默认态阶段面板直接显示第一阶段(时刻 0 即在首阶段内),信息完整', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const panel = screen.getByTestId('fc-stage-panel')
    expect(panel.textContent).toContain('阶段 1/5')
    expect(panel.textContent).toContain('正常传输')
    expect(panel.textContent).toContain('#4–#5') // 起止报文可见
    expect(panel.textContent).toContain('0.030–0.040s') // 时刻区间可见
    expect(panel.textContent!.length).toBeGreaterThan(30) // 要点非空
  })

  it('点击某阶段块后,阶段面板切换为该阶段的完整要点(不依赖 hover)', () => {
    const vm = makeVm()
    const { container } = render(<FaultCompare vm={vm} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    // 点击「重传回补」阶段块
    const stageBlocks = [...container.querySelectorAll('.fc-stage')]
    const retx = stageBlocks.find((el) => el.textContent?.includes('重传回补'))
    expect(retx).toBeTruthy()
    fireEvent.click(retx!)
    const panel = screen.getByTestId('fc-stage-panel')
    expect(panel.textContent).toContain('重传回补')
    expect(panel.textContent).toContain('seq=101')
  })

  it('键盘/静态模式:jsdom 无 matchMedia 时进入静态模式,给出解释且单步仍可用(不允许静默失败)', () => {
    const { container } = render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const wrap = container.querySelector('.fc-wrap') as HTMLElement
    expect(wrap).toBeTruthy()
    // 初始即静态模式(jsdom 缺 matchMedia -> 保守降级):解释文案可见,不静默失败
    expect(screen.getByText(/减少动效/)).toBeTruthy()
    // 静态模式下全部阶段信息完整可见(信息等价)
    const band = screen.getByTestId('fc-stageband')
    for (const label of ['正常传输', '缺口显露', '重传回补', '恢复']) {
      expect(band.textContent).toContain(label)
    }
    // 静态模式下"上一/下一阶段"可用:点击后阶段面板切换到第 2 阶段(阶段遍历无动画,安全)
    fireEvent.click(screen.getByRole('button', { name: '下一阶段' }))
    const panel = screen.getByTestId('fc-stage-panel')
    expect(panel.textContent).toContain('阶段 2/5')
    // Space = 用户显式选择 -> 覆盖静态模式开始播放(phase 离开 static)
    fireEvent.keyDown(wrap, { key: ' ' })
    expect(screen.queryByText(/减少动效/)).toBeNull()
  })

  it('右栏示意基线不含任何真实包号(数据保真红线)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    const right = screen.getByLabelText('正常参考示意')
    for (const n of [4, 6, 7, 12, 13]) {
      expect(right.textContent).not.toContain(`#${n}`)
    }
    expect(right.textContent).toContain('示意')
  })

  it('左栏报文角色标注醒目可见,点击跳回原报文', () => {
    const onSel = vi.fn()
    render(<FaultCompare vm={makeVm()} onSelectPacket={onSel} onBack={vi.fn()} />)
    const msgs = screen.getByTestId('fc-messages')
    expect(msgs.textContent).toContain('缺口显露')
    expect(msgs.textContent).toContain('重传回补')
    expect(msgs.textContent).toContain('恢复')
    fireEvent.click(screen.getByRole('button', { name: '#12' }))
    expect(onSel).toHaveBeenCalledWith(12)
  })

  it('限制层始终展开可见(观察/推断/限制分离)', () => {
    render(<FaultCompare vm={makeVm()} onSelectPacket={vi.fn()} onBack={vi.fn()} />)
    expect(screen.getByText(/单观察点抓包/)).toBeTruthy()
    expect(screen.getByText(/无法排除抓包点自身漏包/)).toBeTruthy()
  })

  it('vm=null 时渲染空态并提供返回入口', () => {
    const onBack = vi.fn()
    render(<FaultCompare vm={null} onSelectPacket={vi.fn()} onBack={onBack} />)
    expect(screen.getByTestId('fault-compare-empty').textContent).toContain('未检出可解释的 TCP 事件')
    fireEvent.click(screen.getByText('返回会话视图'))
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
