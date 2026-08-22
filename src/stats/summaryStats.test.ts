import { describe, expect, it } from 'vitest'
import { deriveSummary } from './summaryStats'
import type { Conversation } from '../model/types'

function conv(id: string, protocol: string, bytes: number, start: number, end: number, issues: Conversation['issues']): Conversation {
  return { id, client: 'a:80', server: 'b:443', protocol, packetCount: 2, bytes, start, end, duration: end - start, packets: [], issues }
}

describe('deriveSummary', () => {
  it('汇总计数与时长', () => {
    const s = deriveSummary([conv('1', 'http', 100, 1, 3, []), conv('2', 'dns', 50, 5, 9, [])])
    expect(s.conversationCount).toBe(2)
    expect(s.packetCount).toBe(4)
    expect(s.totalBytes).toBe(150)
    expect(s.duration).toBe(8)
    expect(s.issueConversations).toBe(0)
  })

  it('协议与异常类型按数量降序', () => {
    const s = deriveSummary([
      conv('1', 'http', 60, 0, 1, [{ type: 'rst', message: 'RST' }, { type: 'no-close', message: 'no' }]),
      conv('2', 'http', 60, 2, 3, [{ type: 'rst', message: 'RST' }]),
      conv('3', 'tcp', 60, 4, 5, []),
    ])
    expect(s.protocolCounts[0]).toEqual({ protocol: 'http', count: 2 })
    expect(s.issueTypeCounts[0]).toEqual({ type: 'rst', count: 2 })
    expect(s.issueConversations).toBe(2)
  })

  it('topHosts 取字节前 5', () => {
    const s = deriveSummary([
      conv('1', 'http', 100, 0, 1, []),
      conv('2', 'dns', 300, 2, 3, []),
    ])
    // a 与 b 各涉 2 会话,a:400,b:400
    expect(s.topHosts).toHaveLength(2)
    expect(s.topHosts[0].bytes).toBe(400)
  })
})
