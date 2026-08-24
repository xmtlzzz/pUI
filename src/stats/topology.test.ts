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

  it('仅 2 台主机时节点水平排列(不排成竖线)', () => {
    // 真实常见:小会话集全部集中在两台主机之间
    const convs = [conv('1', 'a:80', 'b:443', 100), conv('2', 'a:80', 'b:443', 60)]
    const t = buildTopology(convs)
    expect(t.nodes).toHaveLength(2)
    expect(Math.abs(t.nodes[0].y - t.nodes[1].y)).toBeLessThan(1e-9) // 同一水平线
    expect(t.nodes[0].x).not.toBe(t.nodes[1].x)
  })

  it('空输入', () => {
    const t = buildTopology([])
    expect(t.nodes).toEqual([])
    expect(t.edges).toEqual([])
  })

  it('边 key 含分隔符:无分隔符拼接会碰撞的 IP 对 key 各不相同', () => {
    // ("1.1.1.1","23.0.0.5") 与 ("1.1.1.12","3.0.0.5") 无分隔符拼接同为 "1.1.1.123.0.0.5"
    const SEP = String.fromCharCode(0)
    const convs = [conv('1', '1.1.1.1:1000', '23.0.0.5:80', 100), conv('2', '1.1.1.12:2000', '3.0.0.5:80', 50)]
    const t = buildTopology(convs)
    expect(t.edges).toHaveLength(2)
    expect(t.edges[0].key).not.toBe(t.edges[1].key)
    // key 与 from/to 的无分隔符拼接不同(证明含分隔符)
    for (const e of t.edges) {
      expect(e.key).toBe(e.from < e.to ? e.from + SEP + e.to : e.to + SEP + e.from)
      expect(new Set(t.edges.map((x) => x.key)).size).toBe(t.edges.length)
    }
  })
})
