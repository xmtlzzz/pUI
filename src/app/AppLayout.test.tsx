// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, fireEvent, waitFor } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { AppLayout } from './AppLayout'
import { useApp, selectSelected } from '../state/appStore'
import { parsePackets } from '../parse/parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { collectFilterOptions } from '../filter/filterConversations'

function loadHttpFixture() {
  const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/http.json'), 'utf-8')
  const packets = parsePackets(raw)
  const conversations = aggregateConversations(packets)
  const conv = conversations[0]
  return { packets, conversations, conv }
}

describe('AppLayout smoke (real http fixture)', () => {
  it('renders conversation list, sequence diagram, and packet detail from real data', async () => {
    // 阻止浏览器回退路径的真实 fetch(jsdom 无服务器)
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))

    const { packets, conversations, conv } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      meta: { fileName: 'http.pcapng', packetCount: packets.length, interfaces: 1, timeStart: 0, timeEnd: 0.26, fileSize: 936 },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: conv.id,
      diagramStyle: 'A',
    })

    const { container, getByText } = render(<AppLayout />)

    // 会话列表显示 HTTP 会话(协议 badge)
    await waitFor(() => expect(container.querySelector('.cl-row .badge')?.textContent).toBe('http'))
    expect(container.querySelectorAll('.cl-row')).toHaveLength(1)

    // 时序图渲染全部报文
    const msgs = container.querySelectorAll('.msg')
    expect(msgs).toHaveLength(packets.length)

    // 点击第一个报文 → 详情条出现帧号
    fireEvent.click(msgs[0])
    await waitFor(() => expect(getByText(/报文详情 · #1/)).toBeTruthy())
    expect(selectSelected(useApp.getState())?.packets.length).toBe(packets.length)

    vi.unstubAllGlobals()
  })

  it('打开文件后未选中会话 → 点击会话列表选中 → 时序图渲染且不白屏(真实路径回归)', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))

    const { packets, conversations } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      meta: { fileName: 'http.pcapng', packetCount: packets.length, interfaces: 1, timeStart: 0, timeEnd: 0.26, fileSize: 936 },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, // 未选中:时序图空态
      diagramStyle: 'A',
      searchQuery: '', highlight: [],
    })

    const { container } = render(<AppLayout />)
    expect(container.querySelector('.empty')?.textContent).toContain('选择一个会话')

    // 模拟点击会话列表行 → 选中 → 时序图必须在 hooks 数量一致的前提下正常渲染
    useApp.setState({ selectedId: conversations[0].id })
    await waitFor(() => expect(container.querySelectorAll('.msg').length).toBeGreaterThan(0))
    expect(container.querySelector('.boundary-err')).toBeNull()

    vi.unstubAllGlobals()
  })
})
