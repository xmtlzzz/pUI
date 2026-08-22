import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

export interface HostStat {
  host: string
  conversations: number
  bytes: number
  asClient: number
  asServer: number
  issues: number
  protocols: string[]
}

/** 主机(Endpoint)视角:按 displayHost 归并涉及该主机的会话(竞品研究借鉴清单 #5,差异化点)。
 *  同一会话两侧同主机(如组播/回环)不重复计数;按涉及字节降序。 */
export function aggregateHosts(convs: Conversation[]): HostStat[] {
  const map = new Map<string, HostStat>()
  for (const c of convs) {
    const seen = new Set<string>()
    const add = (host: string, role: 'client' | 'server') => {
      if (!host || host === '?') return
      if (seen.has(host)) return
      seen.add(host)
      let st = map.get(host)
      if (!st) {
        st = { host, conversations: 0, bytes: 0, asClient: 0, asServer: 0, issues: 0, protocols: [] }
        map.set(host, st)
      }
      st.conversations++
      st.bytes += c.bytes
      if (role === 'client') st.asClient++
      else st.asServer++
      st.issues += c.issues.length
      if (!st.protocols.includes(c.protocol)) st.protocols.push(c.protocol)
    }
    add(displayHost(c.client), 'client')
    add(displayHost(c.server), 'server')
  }
  return [...map.values()].sort((a, b) => b.bytes - a.bytes || b.issues - a.issues)
}
