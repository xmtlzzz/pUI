import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'
import { compareHosts } from '../model/ipNum'

export type SortKey = 'start' | 'client' | 'server' | 'protocol' | 'packetCount' | 'bytes' | 'duration'
export type SortDir = 'asc' | 'desc'

/** 会话列头排序(PRD F3):数值字段数值比较;client/server 为 IPv4 时按网络序
 *  (PacketLens 借鉴 #2:词法序在跨网段/同段尾数时是错的),其余文本 locale 比较;
 *  同值回落 start+id 保证稳定 */
export function sortConversations(convs: Conversation[], key: SortKey, dir: SortDir): Conversation[] {
  return [...convs].sort((a, b) => {
    let cmp = 0
    switch (key) {
      case 'start': cmp = a.start - b.start; break
      // client/server 是 host:port 形态:先剥端口(displayHost 兼容 IPv6/MAC),再数值序/词法序
      case 'client': cmp = compareHosts(displayHost(a.client), displayHost(b.client)); break
      case 'server': cmp = compareHosts(displayHost(a.server), displayHost(b.server)); break
      case 'protocol': cmp = a.protocol.localeCompare(b.protocol); break
      case 'packetCount': cmp = a.packetCount - b.packetCount; break
      case 'bytes': cmp = a.bytes - b.bytes; break
      case 'duration': cmp = a.duration - b.duration; break
    }
    if (cmp === 0) cmp = a.start - b.start || a.id.localeCompare(b.id)
    return dir === 'asc' ? cmp : -cmp
  })
}
