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
