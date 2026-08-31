import type { Conversation } from '../model/types'

/**
 * 双观测点会话对齐(对照分析第一层)。
 *
 * 设计前提(不可偏离):两侧各自独立走完整分析链路,这里**只做会话身份对齐**,
 * 绝不跨侧合并字节/重组序列空间 —— 两侧时钟偏移、各侧各自漏包,合并会产出错误结论。
 *
 * 匹配键 = transport + 归一化端点对,与 flowKey 同语义但**不含 tcp.stream**:
 * 两侧抓包的 stream 编号必然不同(tshark 按各自文件从 0 编号),含 stream 永远配不上。
 * 端点对取 client/server 字典序归一(与方向无关),抓包侧主客互换不影响匹配。
 *
 * 同端点对多条流(端口复用/并发连接)时按「时间重叠 + 包数比例」贪心配对,
 * 配不上的进 unmatched —— 贪心而非最优指派是刻意的:O(n²) 候选排序一次扫过,
 * 且对照场景下同键流通常 ≤ 3 条,最优解与贪心解在实践中一致。
 */

export interface AlignedPair {
  sideA: Conversation
  sideB: Conversation
}

export interface UnmatchedSide {
  side: 'A' | 'B'
  conv: Conversation
}

export interface AlignmentResult {
  pairs: AlignedPair[]
  unmatched: UnmatchedSide[]
}

/** 会话身份键:transport + 归一化端点对(不含 tcp.stream,理由见文件头)。
 *  Conversation 模型没有顶层 transport 字段,聚合层也是从 packets[0].transport 判定
 *  client/server 的 —— 这里同源取首包,避免引入第二种口径。
 *  client/server 已是聚合层归一后的 "ip:port" 形态,字典序排序消除方向差异。 */
function pairKeyOf(conv: Conversation): string {
  const transport = conv.packets[0]?.transport ?? 'other'
  const endpoints = [conv.client, conv.server].sort()
  return `${transport}|${endpoints[0]}|${endpoints[1]}`
}

/** 时间重叠占比:重叠时长 / 较短会话时长。
 *  用较短侧做分母:长流吞掉整条短流时占比仍为 1(短流完全落在长流窗口内 = 高度可疑配对)。 */
function overlapRatio(a: Conversation, b: Conversation): number {
  const overlap = Math.min(a.end, b.end) - Math.max(a.start, b.start)
  if (overlap <= 0) return 0
  const shortest = Math.min(a.duration, b.duration)
  // 零时长会话(单包流)无区间可算:有正重叠即视为完全重叠
  if (shortest <= 0) return 1
  return Math.min(1, overlap / shortest)
}

/** 包数比例:较小侧 / 较大侧(1 = 两侧包数一致)。 */
function countRatio(a: Conversation, b: Conversation): number {
  const max = Math.max(a.packetCount, b.packetCount)
  if (max === 0) return 1
  return Math.min(a.packetCount, b.packetCount) / max
}

export function alignConversations(convsA: Conversation[], convsB: Conversation[]): AlignmentResult {
  // 按匹配键分桶,桶内才做贪心 —— 不同端点对之间不存在配对可能
  const bucketsA = new Map<string, Conversation[]>()
  for (const c of convsA) {
    const k = pairKeyOf(c)
    const arr = bucketsA.get(k) ?? []
    arr.push(c)
    bucketsA.set(k, arr)
  }
  const bucketsB = new Map<string, Conversation[]>()
  for (const c of convsB) {
    const k = pairKeyOf(c)
    const arr = bucketsB.get(k) ?? []
    arr.push(c)
    bucketsB.set(k, arr)
  }

  // 候选对打分排序(分数降序 + id 兜底字典序,保证同一输入永远同一配对顺序),
  // 依次取用尚未配对的两侧会话 —— 贪心:全局最高分先占坑
  const candidates: Array<{ score: number; a: Conversation; b: Conversation }> = []
  for (const [key, arrA] of bucketsA) {
    const arrB = bucketsB.get(key)
    if (!arrB) continue
    for (const a of arrA) {
      for (const b of arrB) {
        const or = overlapRatio(a, b)
        const cr = countRatio(a, b)
        // 零重叠不配对:同端点对但时间完全错开的两条流,是不同连接而非同一连接的两侧视角
        if (or <= 0) continue
        candidates.push({ score: or + cr, a, b })
      }
    }
  }
  candidates.sort(
    (x, y) =>
      y.score - x.score ||
      x.a.id.localeCompare(y.a.id) ||
      x.b.id.localeCompare(y.b.id),
  )

  const pairedA = new Set<string>()
  const pairedB = new Set<string>()
  const pairs: AlignedPair[] = []
  for (const cand of candidates) {
    if (pairedA.has(cand.a.id) || pairedB.has(cand.b.id)) continue
    pairedA.add(cand.a.id)
    pairedB.add(cand.b.id)
    pairs.push({ sideA: cand.a, sideB: cand.b })
  }

  // 排序确定性:pairs 按端点对字典序(同键时按 A 侧 id 兜底),unmatched 按包数降序
  pairs.sort(
    (x, y) =>
      pairKeyOf(x.sideA).localeCompare(pairKeyOf(y.sideA)) ||
      x.sideA.id.localeCompare(y.sideA.id),
  )

  const unmatched: UnmatchedSide[] = []
  for (const c of convsA) if (!pairedA.has(c.id)) unmatched.push({ side: 'A', conv: c })
  for (const c of convsB) if (!pairedB.has(c.id)) unmatched.push({ side: 'B', conv: c })
  unmatched.sort((x, y) => y.conv.packetCount - x.conv.packetCount || x.side.localeCompare(y.side) || x.conv.id.localeCompare(y.conv.id))

  return { pairs, unmatched }
}
