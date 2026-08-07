// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { SequenceDiagram } from './SequenceDiagram'
import type { Conversation, Packet } from '../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', direction: 'response', info: 'TCP SYN-ACK' },
  { number: 3, time: 0.05, len: 130, transport: 'tcp', proto: 'http', direction: 'request', info: 'HTTP GET /' },
]
const conv: Conversation = {
  id: 'k',
  client: '192.168.1.10:54321',
  server: '93.184.216.34:80',
  protocol: 'http',
  packetCount: 3,
  bytes: 250,
  start: 0,
  end: 0.05,
  duration: 0.05,
  packets,
}

describe('SequenceDiagram', () => {
  it('renders one arrow group per packet', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} />)
    expect(container.querySelectorAll('.msg')).toHaveLength(3)
  })

  it('emits onSelect with packet number on click', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} />)
    const g = container.querySelectorAll('.msg')[0] as Element
    fireEvent.click(g)
    expect(onSelect).toHaveBeenCalledWith(1)
  })

  it('renders an empty state when no conversation selected', () => {
    const onSelect = vi.fn()
    const { getByText } = render(<SequenceDiagram conv={null} style="A" onSelect={onSelect} />)
    expect(getByText(/选择一个会话/)).toBeTruthy()
  })
})
