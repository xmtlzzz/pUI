// @vitest-environment jsdom
import { describe, expect, it, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { ConversationList } from './ConversationList'
import { useApp } from '../state/appStore'
import type { AppState } from '../state/appStore'
import type { Conversation } from '../model/types'

function conv(id: string): Conversation {
  return { id, client: `c${id}`, server: `s${id}`, protocol: 'tcp', packetCount: 1, bytes: 60, start: 0, end: 0, duration: 0, packets: [], issues: [] }
}

const emptyState: Partial<AppState> = {
  meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
  filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
  selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
}

describe('ConversationList 超长列表', () => {
  beforeEach(() => {
    useApp.setState(emptyState)
  })

  it('超过 1000 个会话时只渲染前 1000 行并显示提示', () => {
    const many: Conversation[] = []
    for (let i = 0; i < 1500; i++) many.push(conv(`k${i}`))
    useApp.setState({ filtered: many, conversations: many })
    const { container, getByText } = render(<ConversationList />)
    expect(container.querySelectorAll('tbody tr').length).toBe(1000)
    expect(getByText(/已显示前 1000 个会话/)).toBeTruthy()
  })

  it('未超限时完整渲染全部会话', () => {
    const few = [conv('a'), conv('b')]
    useApp.setState({ filtered: few, conversations: few })
    const { container } = render(<ConversationList />)
    expect(container.querySelectorAll('tbody tr').length).toBe(2)
  })
})
