import { describe, expect, it } from 'vitest'
import { buildTopology } from './stats/topology'
import type { Conversation } from './model/types'

function conv(id: string, client: string, server: string): Conversation {
  return { id, client, server, protocol: 'tcp', packetCount: 2, bytes: 100, start: 0, end: 1, duration: 1, packets: [], issues: [] }
}

describe('topology layout probe', () => {
  it('2D 圆周坐标打印', () => {
    const convs = [
      conv('1', 'a:80', 'b:443'),
      conv('2', 'a:80', 'c:53'),
      conv('3', 'b:443', 'c:53'),
      conv('4', 'a:80', 'd:53'),
      conv('5', 'a:80', 'e:53'),
      conv('6', 'a:80', 'f:53'),
    ]
    const t = buildTopology(convs)
    console.log('nodes:', JSON.stringify(t.nodes.map((n) => ({ h: n.host, x: n.x, y: n.y }))))
    expect(t.nodes.length).toBe(6)
  })
})