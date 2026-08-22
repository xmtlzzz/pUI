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
