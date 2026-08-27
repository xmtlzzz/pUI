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
