import type { Conversation } from '../model/types'

export type SortKey = 'start' | 'client' | 'server' | 'protocol' | 'packetCount' | 'bytes' | 'duration'
export type SortDir = 'asc' | 'desc'

/** 会话列头排序(PRD F3):数值字段数值比较,文本字段 locale 比较;同值回落 start+id 保证稳定 */
export function sortConversations(convs: Conversation[], key: SortKey, dir: SortDir): Conversation[] {
  return [...convs].sort((a, b) => {
    let cmp = 0
    switch (key) {
      case 'start': cmp = a.start - b.start; break
      // numeric:带端口的 IP(192.168.1.2:443)按数字段比较,而非词法(1.10 < 1.2)
      case 'client': cmp = a.client.localeCompare(b.client, undefined, { numeric: true }); break
      case 'server': cmp = a.server.localeCompare(b.server, undefined, { numeric: true }); break
      case 'protocol': cmp = a.protocol.localeCompare(b.protocol); break
      case 'packetCount': cmp = a.packetCount - b.packetCount; break
      case 'bytes': cmp = a.bytes - b.bytes; break
      case 'duration': cmp = a.duration - b.duration; break
    }
    if (cmp === 0) cmp = a.start - b.start || a.id.localeCompare(b.id)
    return dir === 'asc' ? cmp : -cmp
  })
}
