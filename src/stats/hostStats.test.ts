import { describe, expect, it } from 'vitest'
import { aggregateHosts } from './hostStats'
import type { Conversation } from '../model/types'

function conv(id: string, client: string, server: string, bytes: number, issues: Conversation['issues'], protocol = 'http'): Conversation {
  return { id, client, server, protocol, packetCount: 2, bytes, start: 0, end: 1, duration: 1, packets: [], issues }
}

describe('aggregateHosts', () => {
  it('按主机归并涉及字节,按字节降序', () => {
    const list = [
      conv('1', 'a:80', 'b:443', 100, []),
      conv('2', 'a:80', 'c:53', 500, []),
    ]
    const hosts = aggregateHosts(list)
    expect(hosts.map((h) => h.host)).toEqual(['a', 'c', 'b'])
    expect(hosts[0]).toMatchObject({ host: 'a', conversations: 2, bytes: 600 })
    expect(hosts[0].asClient).toBe(2)
    expect(hosts[1].asServer).toBe(1)
  })

  it('同一会话两侧同主机不重复计数', () => {
    const list = [conv('1', '10.0.0.1:1111', '10.0.0.1:2222', 300, [])]
    const hosts = aggregateHosts(list)
    expect(hosts).toHaveLength(1)
    expect(hosts[0].conversations).toBe(1)
  })

  it('统计异常数与协议集合,忽略未知端点', () => {
    const list = [
      conv('1', 'a:80', '?', 100, [{ type: 'rst', message: 'RST' }]),
      conv('2', 'a:80', 'b:53', 200, [], ),
    ]
    const hosts = aggregateHosts(list)
    const a = hosts.find((h) => h.host === 'a')
    expect(a?.issues).toBe(1)
    expect(a?.protocols).toEqual(['http'])
    expect(hosts.find((h) => h.host === '?')).toBeUndefined()
    expect(hosts.find((h) => h.host === 'b')?.protocols).toEqual(['http'])
  })
})
