// @vitest-environment jsdom
import { afterEach, describe, expect, it, beforeEach } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'
afterEach(cleanup)
import { TopologyPanel } from './TopologyPanel'
import { useApp } from '../state/appStore'
import type { Conversation } from '../model/types'

function conv(id: string, client: string, server: string, bytes: number): Conversation {
  return { id, client, server, protocol: 'tcp', packetCount: 2, bytes, start: 0, end: 1, duration: 1, packets: [], issues: [] }
}

describe('TopologyPanel 交互', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
      searchQuery: '', highlight: [],
    })
  })

  it('滚轮缩放改变视图变换', () => {
    useApp.setState({ conversations: [conv('1', 'a:80', 'b:443', 100), conv('2', 'a:80', 'c:53', 50)] })
    const { container } = render(<TopologyPanel />)
    const g = container.querySelector('svg g') as SVGGElement
    const before = g.getAttribute('transform') ?? ''
    fireEvent.wheel(container.querySelector('svg') as Element, { deltaY: -100 })
    const after = g.getAttribute('transform') ?? ''
    expect(after).not.toBe(before)
    expect(after).toContain('scale(1.15)')
  })

  it('空白拖拽平移画布', () => {
    useApp.setState({ conversations: [conv('1', 'a:80', 'b:443', 100), conv('2', 'a:80', 'c:53', 50)] })
    const { container } = render(<TopologyPanel />)
    const svg = container.querySelector('svg') as Element
    const g0 = container.querySelector('svg g') as SVGGElement
    const before = g0.getAttribute('transform') ?? ''
    fireEvent.pointerDown(svg, { clientX: 100, clientY: 100, pointerId: 1 })
    fireEvent.pointerMove(svg, { clientX: 140, clientY: 130, pointerId: 1 })
    fireEvent.pointerUp(svg, { pointerId: 1 })
    const after = g0?.getAttribute('transform') ?? (container.querySelector('svg g') as SVGGElement).getAttribute('transform') ?? ''
    expect(after).not.toBe(before)
    expect(after).toContain('translate(56 38)') // 100→140,100→130 偏移
  })
})