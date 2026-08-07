// @vitest-environment jsdom
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'
import { FilterPanel } from './FilterPanel'
import { useApp } from '../state/appStore'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { collectFilterOptions } from '../filter/filterConversations'
import { emptyFilter } from '../model/types'
import type { Packet } from '../model/types'

function pkt(n: number, proto: string, srcIp: string, srcPort: number, dstIp: string, dstPort: number, transport: 'tcp' | 'udp' = 'tcp'): Packet {
  return { number: n, time: n, len: 60, transport, proto, srcIp, dstIp, srcPort, dstPort, direction: 'other' }
}

beforeEach(() => {
  const packets = [
    pkt(1, 'tcp', '192.168.1.10', 54321, '93.184.216.34', 80),
    pkt(2, 'http', '192.168.1.10', 54321, '93.184.216.34', 80),
    pkt(3, 'dns', '192.168.1.10', 54322, '8.8.8.8', 53, 'udp'),
  ]
  const conversations = aggregateConversations(packets)
  useApp.setState({
    packets,
    conversations,
    filtered: conversations,
    options: collectFilterOptions(packets),
    filter: emptyFilter(),
    meta: null,
    selectedId: null,
    selectedPacket: null,
    diagramStyle: 'A',
  })
})

afterEach(() => {
  cleanup()
})

describe('FilterPanel auto-refresh', () => {
  it('adds a protocol chip and narrows the filtered list immediately', () => {
    const { container } = render(<FilterPanel />)
    const btn = container.querySelectorAll('.fselect')[0] // 协议
    expect(useApp.getState().filter.protocol).toEqual([])
    expect(useApp.getState().filtered).toHaveLength(2)

    fireEvent.click(btn)
    const menu = document.querySelector('.fmenu')
    expect(menu).toBeTruthy()
    const httpItem = Array.from(menu!.querySelectorAll('.fitem')).find((el) => el.textContent?.includes('http'))
    expect(httpItem).toBeTruthy()
    fireEvent.click(httpItem!)

    expect(useApp.getState().filter.protocol).toEqual(['http'])
    expect(useApp.getState().filtered).toHaveLength(1)
    expect(useApp.getState().filtered[0].protocol).toBe('http')
  })

  it('removes a chip and widens the filtered list immediately', () => {
    useApp.setState({ filter: { ...emptyFilter(), protocol: ['http'] }, filtered: [] })
    const { container } = render(<FilterPanel />)

    // 先点掉 http chip → 恢复全部
    const chip = Array.from(container.querySelectorAll('.badge')).find((el) => el.textContent?.includes('http'))
    expect(chip).toBeTruthy()
    fireEvent.click(chip!)

    expect(useApp.getState().filter.protocol).toEqual([])
    expect(useApp.getState().filtered).toHaveLength(2)
  })
})
