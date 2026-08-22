// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
afterEach(cleanup)
import { AppLayout } from './AppLayout'
import { useApp } from '../state/appStore'
import { parsePackets } from '../parse/parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { collectFilterOptions } from '../filter/filterConversations'

describe('报文点击全遍历(详情无崩溃回归)', () => {
  it('mixed 示例逐个点击报文,详情面板始终渲染', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server'))))
    const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/mixed.json'), 'utf-8')
    const packets = parsePackets(raw)
    const conversations = aggregateConversations(packets)
    useApp.setState({
      packets, conversations, filtered: conversations,
      options: collectFilterOptions(packets),
      meta: { fileName: 'x.pcapng', packetCount: packets.length, interfaces: 1, timeStart: 0, timeEnd: 1, fileSize: 900 },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: conversations[0].id,
      diagramStyle: 'A', searchQuery: '', highlight: [],
    })
    const { container } = render(<AppLayout />)
    const msgs = container.querySelectorAll('.msg')
    expect(msgs.length).toBeGreaterThan(0)
    for (let i = 0; i < msgs.length; i++) {
      fireEvent.click(msgs[i])
      expect(container.querySelector('.detail-bar')?.textContent?.length ?? 0).toBeGreaterThan(0)
    }
    vi.unstubAllGlobals()
  })
})