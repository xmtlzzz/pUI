import { describe, expect, it } from 'vitest'
import { sortConversations } from './sortConversations'
import type { Conversation } from '../model/types'

function conv(id: string, start: number, bytes: number, packetCount: number, client = 'c', server = 's', protocol = 'tcp'): Conversation {
  return { id, client, server, protocol, packetCount, bytes, start, end: start + 1, duration: 1, packets: [], issues: [] }
}

describe('sortConversations', () => {
  it('start 升序为默认', () => {
    const list = [conv('b', 2, 10, 1), conv('a', 1, 30, 2)]
    expect(sortConversations(list, 'start', 'asc').map((c) => c.id)).toEqual(['a', 'b'])
  })

  it('desc 反转数值方向', () => {
    const list = [conv('a', 1, 10, 1), conv('b', 2, 30, 2)]
    expect(sortConversations(list, 'bytes', 'desc').map((c) => c.id)).toEqual(['b', 'a'])
  })

  it('文本字段按 locale 比较', () => {
    const list = [conv('a', 1, 10, 1, '192.168.1.2'), conv('b', 2, 10, 1, '192.168.1.10')]
    expect(sortConversations(list, 'client', 'asc').map((c) => c.id)).toEqual(['a', 'b'])
  })

  it('client/server 是 IPv4(含 host:port 形态)时按网络序而非词法序(PacketLens 借鉴 #2)', () => {
    // 词法 '192.168.1.2...' < '10.0.0.2...' 是错误网络序;剥端口后 10.x 应在前
    const list = [
      conv('a', 1, 10, 1, '192.168.1.2:443', '10.0.0.9:1234'),
      conv('b', 2, 10, 1, '10.0.0.2:5555', '192.168.1.3:80'),
    ]
    expect(sortConversations(list, 'client', 'asc').map((c) => c.id)).toEqual(['b', 'a'])
    // server 侧:a.server=10.0.0.9 < b.server=192.168.1.3(网络序),a 在前
    expect(sortConversations(list, 'server', 'asc').map((c) => c.id)).toEqual(['a', 'b'])
  })

  it('IPv4 同段尾数按数值比较:10.0.0.2 < 10.0.0.10(词法相反)', () => {
    const list = [
      conv('a', 1, 10, 1, '10.0.0.10:80'),
      conv('b', 2, 10, 1, '10.0.0.2:80'),
    ]
    expect(sortConversations(list, 'client', 'asc').map((c) => c.id)).toEqual(['b', 'a'])
  })

  it('非 IPv4 端点(MAC/IPv6/主机名)保持既有 locale+numeric 词法行为', () => {
    const list = [
      conv('a', 1, 10, 1, 'aa:bb:cc:dd:ee:10'),
      conv('b', 2, 10, 1, 'aa:bb:cc:dd:ee:2'),
    ]
    expect(sortConversations(list, 'client', 'asc').map((c) => c.id)).toEqual(['b', 'a'])
  })

  it('同值时回落 start+id,顺序稳定', () => {
    const list = [conv('b', 1, 10, 1), conv('a', 1, 10, 1)]
    expect(sortConversations(list, 'bytes', 'asc').map((c) => c.id)).toEqual(['a', 'b'])
  })

  it('不改动原数组', () => {
    const list = [conv('b', 2, 10, 1), conv('a', 1, 10, 1)]
    sortConversations(list, 'start', 'asc')
    expect(list.map((c) => c.id)).toEqual(['b', 'a'])
  })
})
