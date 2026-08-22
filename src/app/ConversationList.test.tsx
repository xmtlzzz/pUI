// @vitest-environment jsdom
import { afterEach, describe, expect, it, beforeEach } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'

afterEach(cleanup) // 列表行残留在 body,必须显式清理避免跨用例重复表头
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
  searchQuery: '', highlight: [],
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

  it('展示开始时间列', () => {
    const few = [{ ...conv('a'), start: 1.25, end: 1.25 }]
    useApp.setState({ filtered: few, conversations: few })
    const { container } = render(<ConversationList />)
    expect(container.textContent).toContain('1.25s')
  })

  it('搜索过滤会话并在点击行时设置高亮定位', () => {
    const c1: Conversation = { ...conv('k1'), client: 'a', start: 1, packets: [{ number: 3, time: 0, len: 60, transport: 'tcp', proto: 'http', srcIp: 'a', dstIp: 'b', direction: 'request', info: 'HTTP GET /search' }] }
    const c2: Conversation = { ...conv('k2'), client: 'x', start: 2, packets: [{ number: 5, time: 0, len: 60, transport: 'tcp', proto: 'dns', srcIp: 'x', dstIp: 'y', direction: 'request', dnsQuery: 'other.net' }] }
    useApp.setState({ filtered: [c1, c2], conversations: [c1, c2], searchQuery: '', highlight: [] })
    const { container, getByLabelText } = render(<ConversationList />)
    fireEvent.change(getByLabelText('搜索报文'), { target: { value: 'search' } })
    expect(container.querySelectorAll('tbody tr').length).toBe(1)
    expect(container.textContent).toContain('1 命中')
    fireEvent.click(container.querySelector('tbody tr') as Element)
    expect(useApp.getState().highlight).toEqual([3])
  })

  it('点击表头切换排序(同列再点反向)', () => {
    const mk = (id: string, client: string, duration: number): Conversation => ({
      ...conv(id),
      client,
      start: Number(id), // a=1, b=2, c=3
      end: Number(id) + 1,
      bytes: 100,
      packetCount: 1,
      duration,
    })
    const list = [mk('a', 'c1', 33), mk('b', 'c2', 11), mk('c', 'c3', 22)]
    useApp.setState({ filtered: list, conversations: list, sortKey: 'start', sortDir: 'asc' })
    const { container, getByText } = render(<ConversationList />)
    fireEvent.click(getByText(/时长/))
    // 按 duration 升序:b(11) → c(22) → a(33)
    expect(container.querySelectorAll('tbody tr')[0].textContent).toContain('c2')
    fireEvent.click(getByText(/时长/))
    // 再点 → 降序:a(33) → c(22) → b(11)
    expect(container.querySelectorAll('tbody tr')[0].textContent).toContain('c1')
  })
})
