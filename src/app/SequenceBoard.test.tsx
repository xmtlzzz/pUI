// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { SequenceBoard } from './SequenceBoard'
import { useApp, selectSelected } from '../state/appStore'
import { parsePackets } from '../parse/parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'

afterEach(cleanup)

function loadHttpFixture() {
  const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/http.json'), 'utf-8')
  const packets = parsePackets(raw)
  const conversations = aggregateConversations(packets)
  return { packets, conversations, conv: conversations[0] }
}

describe('SequenceBoard 时序图整页板块(用户要求:长会话交互整页可读)', () => {
  it('未选中会话时渲染空态引导与返回', () => {
    const onClose = vi.fn()
    render(<SequenceBoard onClose={onClose} />)
    expect(screen.getByTestId('seq-board-empty')).toBeTruthy()
    fireEvent.click(screen.getByTestId('seq-board-back'))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('整页渲染时序图与详情区;点报文后详情显示帧号;返回回调;缩放按钮改变画布尺寸', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    const { packets, conversations, conv } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      selectedId: conv.id,
      diagramStyle: 'A',
      timeMode: 'relative',
    })
    const selected = selectSelected(useApp.getState())
    expect(selected).not.toBeNull()
    const onClose = vi.fn()
    const { container } = render(<SequenceBoard onClose={onClose} />)

    // 整页画布与时序图消息节点存在
    expect(screen.getByTestId('seq-board-canvas')).toBeTruthy()
    const msgsBefore = container.querySelectorAll('.msg').length
    expect(msgsBefore).toBe(packets.length)

    // 点第一个报文 → 详情联动(显示帧号)
    fireEvent.click(container.querySelector('.msg')!)
    expect(container.textContent).toContain('报文详情 · #1')

    // 缩放:画布 SVG 盒尺寸随 zoom 放大(1 → 1.1)
    const svgBefore = Number(container.querySelector('.seq-board-canvas svg')?.getAttribute('width'))
    fireEvent.click(screen.getByTestId('seq-board-zoom-in'))
    const svgAfter = Number(container.querySelector('.seq-board-canvas svg')?.getAttribute('width'))
    expect(svgAfter).toBeGreaterThan(svgBefore)

    // 返回
    fireEvent.click(screen.getByTestId('seq-board-back'))
    expect(onClose).toHaveBeenCalledOnce()
    act(() => {
      useApp.setState({ selectedId: null })
    })
    vi.unstubAllGlobals()
  })
})
