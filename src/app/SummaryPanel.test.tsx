// @vitest-environment jsdom
import { describe, expect, it, beforeEach } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { SummaryPanel } from './SummaryPanel'
import { useApp } from '../state/appStore'
import type { Conversation, Packet } from '../model/types'

function pkt(n: number, analysis?: string[]): Packet {
  return { number: n, time: n, len: 60, transport: 'tcp', proto: 'tcp', direction: 'other', tcpAnalysis: analysis }
}

function conv(id: string, packets: Packet[]): Conversation {
  return {
    id, client: '1.1.1.1:5000', server: '2.2.2.2:80', protocol: 'http',
    packetCount: packets.length, bytes: 60 * packets.length,
    start: 0, end: packets.length, duration: packets.length, packets, issues: [],
  }
}

describe('SummaryPanel TCP 异常统计', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
      searchQuery: '', highlight: [], timeRange: null,
    })
  })

  it('未选中会话时不渲染统计表', () => {
    useApp.setState({ conversations: [conv('1', [pkt(1, ['retransmission'])])], selectedId: null })
    const { container } = render(<SummaryPanel />)
    expect(container.querySelector('.tcp-stat')).toBeNull()
  })

  it('选中会话后按报文级计数渲染表格行', () => {
    useApp.setState({
      conversations: [conv('1', [pkt(1, ['retransmission']), pkt(2, ['retransmission']), pkt(3, ['duplicate-ack'])])],
      selectedId: '1',
    })
    const { container } = render(<SummaryPanel />)
    const rows = [...container.querySelectorAll('.tcp-stat-row')]
    expect(rows).toHaveLength(2)
    expect(rows[0].textContent).toContain('重传')
    expect(rows[0].querySelector('.num')?.textContent).toBe('2')
    expect(rows[1].textContent).toContain('重复 ACK')
    expect(rows[1].querySelector('.num')?.textContent).toBe('1')
  })

  it('无异常会话显示占位提示而非空表', () => {
    useApp.setState({ conversations: [conv('1', [pkt(1)])], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    expect(container.querySelector('.tcp-stat')).toBeNull()
    expect(container.textContent).toContain('无重传/乱序等标记')
  })

  it('点击行下钻:高亮该类标签的全部报文号', () => {
    useApp.setState({
      conversations: [conv('1', [pkt(1, ['retransmission']), pkt(2), pkt(3, ['out-of-order']), pkt(4, ['retransmission'])])],
      selectedId: '1',
    })
    const { container } = render(<SummaryPanel />)
    const retransRow = [...container.querySelectorAll('.tcp-stat-row')].find((r) => r.textContent?.includes('重传'))
    fireEvent.click(retransRow!)
    expect(useApp.getState().highlight).toEqual([1, 4])
  })

  it('解读文案随内容变动:大量(占比≥10%)与个位数措辞不同', () => {
    // 10 包里 2 个重传 = 20% → 「大量」
    useApp.setState({
      conversations: [conv('1', [pkt(1, ['retransmission']), pkt(2, ['retransmission']), ...Array.from({ length: 8 }, (_, i) => pkt(i + 3))])],
      selectedId: '1',
    })
    const { container } = render(<SummaryPanel />)
    const hint = container.querySelector('.tcp-stat-row .hint')?.textContent ?? ''
    expect(hint).toContain('大量')
    expect(hint).toContain('20.0%')
  })
})

describe('SummaryPanel M5 会话测量(RTT 近似 + 采集质量)', () => {
  it('样本充足时显示 RTT 分位数;样本不足显示 unavailable(不编造数字)', () => {
    // 8 个确认事件 → 样本充足
    const rich: Packet[] = []
    for (let i = 0; i < 8; i++) {
      rich.push({ ...pkt(i * 2 + 1), time: i, tcpFlags: '0x0018', tcpSeq: 1 + i * 100, tcpLen: 100, srcPort: 5000, dstPort: 80 })
      rich.push({ ...pkt(i * 2 + 2), time: i + 0.02, tcpFlags: '0x0010', tcpAck: 1 + (i + 1) * 100, srcPort: 80, dstPort: 5000 })
    }
    useApp.setState({ conversations: [conv('1', rich)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const m5 = container.querySelector('[data-testid="summary-m5"]')!
    expect(m5.textContent).toContain('RTT p50 20ms') // 0.02s ≈ 20ms
    expect(m5.textContent).toContain('样本 8')
    expect(m5.textContent).not.toContain('RTT p90 unavailable') // RTT 可用;截断占比因无 capLen 而 unavailable 与本用例无关

    // 1 个确认事件 → 不足
    const poor: Packet[] = [
      { ...pkt(1), time: 0, tcpFlags: '0x0018', tcpSeq: 1, tcpLen: 100, srcPort: 5000, dstPort: 80 },
      { ...pkt(2), time: 0.02, tcpFlags: '0x0010', tcpAck: 101, srcPort: 80, dstPort: 5000 },
    ]
    const view2 = render(<SummaryPanel />)
    view2.unmount()
    useApp.setState({ conversations: [conv('1', poor)], selectedId: '1' })
    const v = render(<SummaryPanel />)
    const m5b = v.container.querySelector('[data-testid="summary-m5"]')!
    expect(m5b.textContent).toContain('unavailable')
  })

  it('有截断帧时显示计数/占比与采集侧警示;capLen 缺失显示 unavailable', () => {
    const packets: Packet[] = [
      { ...pkt(1), capLen: 54 }, // 100B?len=60 → 54<60 截断
      { ...pkt(2), capLen: 60 },
    ]
    useApp.setState({ conversations: [conv('1', packets)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const m5 = container.querySelector('[data-testid="summary-m5"]')!
    expect(m5.textContent).toContain('截断帧')
    expect(container.textContent).toContain('采集侧信号')
    // capLen 全缺失
    useApp.setState({ conversations: [conv('1', [pkt(3), pkt(4)])], selectedId: '1' })
    const v2 = render(<SummaryPanel />)
    expect(v2.container.querySelector('[data-testid="summary-m5"]')!.textContent).toContain('unavailable')
  })
})

describe('SummaryPanel 窗口统计', () => {
  it('窗口通告可用时显示 min/max/变化次数;零窗口期单列', () => {
    const packets: Packet[] = [
      { ...pkt(1), tcpFlags: '0x0018', tcpLen: 100, srcPort: 5000, dstPort: 80 },
      { ...pkt(2), tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 65535, srcPort: 80, dstPort: 5000 },
      { ...pkt(3), tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 0, srcPort: 80, dstPort: 5000 },
      { ...pkt(4), tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 0, srcPort: 80, dstPort: 5000 },
      { ...pkt(5), tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 8760, srcPort: 80, dstPort: 5000 },
    ]
    useApp.setState({ conversations: [conv('1', packets)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const m5 = container.querySelector('[data-testid="summary-m5"]')!
    expect(m5.textContent).toContain('窗口 min')
    expect(m5.textContent).toContain('0.0KB') // 0 → 0.0KB
    expect(m5.textContent).toContain('窗口变化')
    expect(m5.textContent).toContain('零窗口期')
  })
})

describe('SummaryPanel 健康分(仅筛选用)', () => {
  it('健康会话显示高分;有扣分时明细逐项可见', () => {
    useApp.setState({ conversations: [conv('1', [pkt(1)])], selectedId: '1' }) // 单包 TCP:无扣分
    const { container } = render(<SummaryPanel />)
    const h = container.querySelector('[data-testid="summary-health"]')!
    expect(h.textContent).toContain('健康分')
    expect(h.textContent).toContain('health-v1')
    expect(h.textContent).toContain('仅筛选用')
    // 无扣分时不显示明细
    expect(h.textContent).not.toContain('(-')

    // 带 RST:显示扣分明细
    const rst: Packet[] = [{ ...pkt(1), tcpFlags: '0x0004' }]
    useApp.setState({ conversations: [conv('1', rst)], selectedId: '1' })
    const v2 = render(<SummaryPanel />)
    expect(v2.container.querySelector('[data-testid="summary-health"]')!.textContent).toContain('(-15)')
  })
})

describe('SummaryPanel 应用层事件(M6 插件接入)', () => {
  it('选中 HTTP 会话时显示请求/响应计数;慢响应超阈值列出并可点击高亮', () => {
    const httpPkts: Packet[] = [
      { ...pkt(1), proto: 'http', httpMethod: 'GET', httpUri: '/api' },
      { ...pkt(2), proto: 'http', httpCode: '200', httpTime: 0.2 },
      { ...pkt(3), proto: 'http', httpMethod: 'GET', httpUri: '/slow' },
      { ...pkt(4), proto: 'http', httpCode: '504', httpTime: 2.5 }, // > 默认慢阈值 1s
    ]
    useApp.setState({ conversations: [conv('1', httpPkts)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const grid = container.querySelector('[data-testid="summary-app"]')!
    expect(grid.textContent).toContain('HTTP 请求')
    expect(grid.textContent).toContain('HTTP 响应')
    // 慢响应区:只有 #4(2.5s > 1s)
    const slow = container.querySelector('[data-testid="summary-app-slow"]')!
    expect(slow.textContent).toContain('#4')
    expect(slow.textContent).not.toContain('#2')
    // 点击慢响应 → 高亮该报文(下钻)
    fireEvent.click(slow.querySelector('button')!)
    expect(useApp.getState().highlight).toEqual([4])
  })

  it('无应用字段的 TCP 会话不渲染应用层区', () => {
    useApp.setState({ conversations: [conv('1', [pkt(1)])], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    expect(container.querySelector('[data-testid="summary-app"]')).toBeNull()
  })
})

describe('SummaryPanel 吞吐双条形 + 窗口曲线(统计图形化)', () => {
  it('时间分布区渲染吞吐条形(报文数+KB)与峰值;无报文时不渲染', () => {
    const pkts: Packet[] = [
      { ...pkt(1), time: 0, tcpLen: 1000, srcPort: 5000, dstPort: 80 },
      { ...pkt(2), time: 5, tcpLen: 2000, srcPort: 5000, dstPort: 80 },
      { ...pkt(3), time: 10, tcpLen: 500, srcPort: 5000, dstPort: 80 },
    ]
    useApp.setState({ packets: pkts, conversations: [conv('1', pkts)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const tp = container.querySelector('[data-testid="summary-throughput"]')!
    expect(tp.querySelectorAll('.tp-bar')).toHaveLength(24) // 与报文数直方图同 24 桶
    expect(tp.textContent).toContain('峰值')
    expect(tp.textContent).toContain('KB')
    // 无报文:时间分布吞吐区不渲染
    useApp.setState({ packets: [], conversations: [] })
    const v2 = render(<SummaryPanel />)
    expect(v2.container.querySelector('[data-testid="summary-throughput"]')).toBeNull()
  })

  it('窗口通告可用时渲染迷你曲线(polyline 点按样本缩放);无窗口字段不渲染', () => {
    const pkts: Packet[] = [
      { ...pkt(1), time: 0, tcpFlags: '0x0018', tcpLen: 100, srcPort: 5000, dstPort: 80 },
      { ...pkt(2), time: 0.02, tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 65535, srcPort: 80, dstPort: 5000 },
      { ...pkt(3), time: 0.04, tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 8760, srcPort: 80, dstPort: 5000 },
      { ...pkt(4), time: 0.06, tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 17520, srcPort: 80, dstPort: 5000 },
    ]
    useApp.setState({ conversations: [conv('1', pkts)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const curve = container.querySelector('[data-testid="summary-win-curve"] polyline')
    expect(curve).not.toBeNull()
    const pts = curve!.getAttribute('points')!
    expect(pts.split(' ').filter(Boolean)).toHaveLength(3) // 3 个变化点样本
    // 无窗口字段:不渲染曲线
    useApp.setState({ conversations: [conv('2', [pkt(5), pkt(6)])], selectedId: '2' })
    const v2 = render(<SummaryPanel />)
    expect(v2.container.querySelector('[data-testid="summary-win-curve"]')).toBeNull()
  })

  it('窗口曲线在单一样本(无变化)时也渲染(不除零)', () => {
    const pkts: Packet[] = [
      { ...pkt(1), time: 0, tcpFlags: '0x0018', tcpLen: 100, srcPort: 5000, dstPort: 80 },
      { ...pkt(2), time: 0.02, tcpFlags: '0x0010', tcpLen: 0, tcpWindow: 65535, srcPort: 80, dstPort: 5000 },
    ]
    useApp.setState({ conversations: [conv('1', pkts)], selectedId: '1' })
    const { container } = render(<SummaryPanel />)
    const curve = container.querySelector('[data-testid="summary-win-curve"] polyline')
    expect(curve).not.toBeNull()
    expect(curve!.getAttribute('points')!.split(' ').filter(Boolean)).toHaveLength(1)
  })
})
