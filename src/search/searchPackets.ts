import type { Conversation } from '../model/types'

export interface ConvMatch {
  convId: string
  numbers: number[]
}

/** 每包小写 haystack 缓存:会话对象长期存活于 store,WeakMap 按对象键弱引用,GC 自动释放,无需手动失效 */
const haystackCache = new WeakMap<Conversation, string[]>()

/** 报文全文搜索:协议/IP/端口/MAC/info/URI/DNS/TCP标志子串匹配(大小写不敏感)。
 *  返回命中的会话与报文号,供会话列表过滤与时序图高亮定位。 */
export function searchConversations(convs: Conversation[], rawQuery: string): ConvMatch[] {
  const q = rawQuery.trim().toLowerCase()
  if (!q) return []
  const out: ConvMatch[] = []
  for (const c of convs) {
    const haystacks = getHaystacks(c)
    const packets = c.packets
    const numbers: number[] = []
    for (let i = 0; i < packets.length; i++) {
      // 已缓存的小写串,单次 includes 即可,免去逐包重建副本
      if (haystacks[i].includes(q)) numbers.push(packets[i].number)
    }
    if (numbers.length) out.push({ convId: c.id, numbers })
  }
  return out
}

/** 每包一次性小写化的拼接串,索引与 c.packets 对齐;'\u0000' 分隔防止跨字段假命中 */
function getHaystacks(c: Conversation): string[] {
  const cached = haystackCache.get(c)
  if (cached) return cached
  const haystacks = c.packets.map((p) =>
    [
      p.proto.toLowerCase(),
      p.info?.toLowerCase(),
      p.srcIp?.toLowerCase(),
      p.dstIp?.toLowerCase(),
      p.srcMac?.toLowerCase(),
      p.dstMac?.toLowerCase(),
      p.srcPort != null ? String(p.srcPort) : undefined,
      p.dstPort != null ? String(p.dstPort) : undefined,
      p.httpUri?.toLowerCase(),
      p.dnsQuery?.toLowerCase(),
      p.httpCode?.toLowerCase(),
      p.tcpFlags?.toLowerCase(),
    ]
      .filter((x): x is string => x != null)
      .join('\u0000'),
  )
  haystackCache.set(c, haystacks)
  return haystacks
}
