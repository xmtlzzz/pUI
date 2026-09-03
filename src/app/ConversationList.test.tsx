// @vitest-environment jsdom
import { afterEach, describe, expect, it, beforeEach, vi } from 'vitest'
import { render, fireEvent, cleanup, act } from '@testing-library/react'

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

  it('超过 1000 个会话时截断 + 窗口化:DOM 只渲染可视窗口行', () => {
    const many: Conversation[] = []
    for (let i = 0; i < 1500; i++) many.push(conv(`k${i}`))
    useApp.setState({ filtered: many, conversations: many })
    const { container, getByText } = render(<ConversationList />)
    expect(getByText(/已显示前 1000 个会话/)).toBeTruthy()
    // 窗口化:固定行高 28 × 视口 600 → 可视 ~21 行 + 每侧缓冲 10 → DOM 远小于 1000
    const rows = container.querySelectorAll('.cl-row')
    expect(rows.length).toBeLessThanOrEqual(60)
    expect(rows.length).toBeGreaterThan(10)
    // 撑高保留全部 1000 行的高度,滚动可达
    const body = container.querySelector('.cl-body') as HTMLElement
    expect(body.style.height).toBe((1000 * 28) + 'px')
  })

  it('滚动后渲染窗口随 scrollTop 移动', () => {
    const many: Conversation[] = []
    for (let i = 0; i < 300; i++) many.push(conv(`k${i}`))
    useApp.setState({ filtered: many, conversations: many })
    const { container } = render(<ConversationList />)
    const scroller = container.querySelector('.cl-scroll') as HTMLElement
    const firstBefore = container.querySelector('.cl-row')?.getAttribute('data-idx')
    scroller.scrollTop = 6000 // ≈ 第 204 行(300 行总高 8400)
    fireEvent.scroll(scroller)
    const rowsAfter = container.querySelectorAll('.cl-row')
    expect(rowsAfter.length).toBeLessThanOrEqual(60)
    const firstAfter = rowsAfter[0]?.getAttribute('data-idx')
    expect(firstAfter).not.toBe(firstBefore)
    expect(Number(firstAfter ?? -1)).toBeGreaterThanOrEqual(190)
  })

  it('未超限时完整渲染全部会话', () => {
    const few = [conv('a'), conv('b')]
    useApp.setState({ filtered: few, conversations: few })
    const { container } = render(<ConversationList />)
    expect(container.querySelectorAll('.cl-row').length).toBe(2)
  })

  it('展示开始时间列', () => {
    const few = [{ ...conv('a'), start: 1.25, end: 1.25 }]
    useApp.setState({ filtered: few, conversations: few })
    const { container } = render(<ConversationList />)
    expect(container.textContent).toContain('1.25s')
  })

  it('搜索过滤会话并在点击行时设置高亮定位', () => {
    // SearchBox 有 200ms 防抖:store 更新发生在定时器之后,用假时钟推进
    vi.useFakeTimers()
    try {
      const c1: Conversation = { ...conv('k1'), client: 'a', start: 1, packets: [{ number: 3, time: 0, len: 60, transport: 'tcp', proto: 'http', srcIp: 'a', dstIp: 'b', direction: 'request', info: 'HTTP GET /search' }] }
      const c2: Conversation = { ...conv('k2'), client: 'x', start: 2, packets: [{ number: 5, time: 0, len: 60, transport: 'tcp', proto: 'dns', srcIp: 'x', dstIp: 'y', direction: 'request', dnsQuery: 'other.net' }] }
      useApp.setState({ filtered: [c1, c2], conversations: [c1, c2], searchQuery: '', highlight: [] })
      const { container, getByLabelText } = render(<ConversationList />)
      fireEvent.change(getByLabelText('搜索报文'), { target: { value: 'search' } })
      act(() => { vi.advanceTimersByTime(250) }) // 越过防抖窗口,store 才收到查询词
      expect(container.querySelectorAll('.cl-row').length).toBe(1)
      expect(container.textContent).toContain('1 命中')
      fireEvent.click(container.querySelector('.cl-row') as Element)
      expect(useApp.getState().highlight).toEqual([3])
    } finally {
      vi.useRealTimers()
    }
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
    expect(container.querySelectorAll('.cl-row')[0].textContent).toContain('c2')
    fireEvent.click(getByText(/时长/))
    // 再点 → 降序:a(33) → c(22) → b(11)
    expect(container.querySelectorAll('.cl-row')[0].textContent).toContain('c1')
  })

  it('搜索有命中时展示 N/M 计数与上一个/下一个导航按钮', () => {
    const c1: Conversation = {
      ...conv('k1'), client: 'a', start: 1,
      packets: [{ number: 3, time: 0, len: 60, transport: 'tcp', proto: 'http', srcIp: 'a', dstIp: 'b', direction: 'request', info: 'HTTP GET /search' }],
    }
    useApp.setState({
      filtered: [c1], conversations: [c1],
      searchQuery: 'search', searchHits: [3], searchHitIndex: 0,
    })
    const { container, getByText } = render(<ConversationList />)
    expect(getByText('1/1')).toBeTruthy() // 计数条
    // 导航按钮存在,且不匹配表头「命中」列文案
    const prev = container.querySelector('[aria-label="上一个命中"]') as HTMLElement
    const next = container.querySelector('[aria-label="下一个命中"]') as HTMLElement
    expect(prev).not.toBeNull()
    expect(next).not.toBeNull()
  })

  it('搜索有命中时点「下一个命中」调用 store 导航并推进计数', () => {
    const c1: Conversation = {
      ...conv('k1'), client: 'a', start: 1,
      packets: [{ number: 3, time: 0, len: 60, transport: 'tcp', proto: 'http', srcIp: 'a', dstIp: 'b', direction: 'request', info: 'HTTP GET /search' }],
    }
    useApp.setState({
      filtered: [c1], conversations: [c1],
      searchQuery: 'search', searchHits: [3], searchHitIndex: 0,
    })
    const { container, getByText } = render(<ConversationList />)
    fireEvent.click(container.querySelector('[aria-label="下一个命中"]') as Element)
    expect(getByText('1/1')).toBeTruthy() // 循环回第一条(3 命中中的第 1 条)
    expect(useApp.getState().searchHitIndex).toBe(0)
    expect(useApp.getState().selectedPacket).toBe(3)
    expect(useApp.getState().highlight).toEqual([3])
  })

  it('搜索无命中时不显示计数条与导航按钮', () => {
    useApp.setState({
      filtered: [conv('k1')], conversations: [conv('k1')],
      searchQuery: 'zzz', searchHits: [], searchHitIndex: -1,
    })
    const { container } = render(<ConversationList />)
    expect(container.querySelector('.search-hit-count')).toBeNull()
    expect(container.querySelector('[aria-label="上一个命中"]')).toBeNull()
    expect(container.querySelector('[aria-label="下一个命中"]')).toBeNull()
  })
})
