// @vitest-environment jsdom
import { describe, expect, it, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { HostPanel } from './HostPanel'
import { useApp } from '../state/appStore'
import type { Conversation } from '../model/types'

function conv(id: string, client: string, server: string, bytes: number, issues = 0): Conversation {
  return { id, client, server, protocol: 'http', packetCount: 2, bytes, start: 0, end: 1, duration: 1, packets: [], issues: issues ? [{ type: 'rst', message: 'RST' }] : [] }
}

describe('HostPanel', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
      searchQuery: '', highlight: [],
    })
  })

  it('表头使用 Host/Client/Server/Error 字样,异常行标红,角色列着色', () => {
    useApp.setState({ conversations: [conv('1', 'a:80', 'b:443', 100, 2)] })
    const { container, getByText } = render(<HostPanel />)
    expect(getByText(/主机 Host/)).toBeTruthy()
    expect(getByText(/Client/)).toBeTruthy()
    expect(getByText(/Server/)).toBeTruthy()
    expect(getByText(/Error/)).toBeTruthy()
    const errRow = container.querySelector('.hp-err')
    expect(errRow?.textContent).toContain('⚠ 1')
    const clientCell = container.querySelector('.hp-role.client')
    expect(clientCell?.textContent).toBe('1')
  })
})