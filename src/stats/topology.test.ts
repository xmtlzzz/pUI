import { describe, expect, it } from 'vitest'
import { buildTopology } from './topology'
import type { Conversation } from '../model/types'

function conv(id: string, client: string, server: string, bytes: number, protocol = 'http', issues = 0): Conversation {
  return { id, client, server, protocol, packetCount: 2, bytes, start: 0, end: 1, duration: 1, packets: [], issues: issues ? [{ type: 'rst', message: 'RST' }] : [] }
}

describe('buildTopology', () => {
  it('Top-N 主机圆周布局,按字节截断', () => {
    const convs = [conv('1', 'a:80', 'b:443', 100), conv('2', 'a:80', 'c:53', 50), conv('3', 'b:443', 'd:53', 30)]
    const t = buildTopology(convs, 2)
    expect(t.nodes.map((n) => n.host)).toEqual(['a', 'b'])
    expect(t.nodes[0].id).toBe('a')
    expect(t.nodes[0].y).not.toBe(t.nodes[1].y) // ±90° 圆周对称,x 相同但 y 不同
  })

  it('同主机对多会话合并为一条边,累计字节与协议', () => {
    const convs = [conv('1', 'a:80', 'b:443', 100, 'http'), conv('2', 'a:80', 'b:443', 500, 'tls', 1)]
    const t = buildTopology(convs)
    expect(t.edges).toHaveLength(1)
    expect(t.edges[0].bytes).toBe(600)
    expect(t.edges[0].protocols).toEqual(['http', 'tls'])
    expect(t.edges[0].convIds).toEqual(['1', '2'])
    expect(t.edges[0].hasIssue).toBe(true)
  })

  it('自环(同一主机)与 Top-N 外端点跳过', () => {
    const convs = [conv('1', 'a:80', 'a:81', 100), conv('2', 'a:80', 'zzz:53', 100)]
    const t = buildTopology(convs, 1)
    expect(t.nodes.map((n) => n.host)).toEqual(['a'])
    expect(t.edges).toHaveLength(0)
  })

  it('空输入', () => {
    const t = buildTopology([])
    expect(t.nodes).toEqual([])
    expect(t.edges).toEqual([])
  })
})