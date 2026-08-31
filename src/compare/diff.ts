import type { Conversation, Packet } from '../model/types'

/**
 * 双点会话差异计算(对照分析第二层)。
 *
 * 输入是**每侧独立**走完既有分析链路后的产物:
 * - sideX:Conversation(聚合层输出)
 * - factsX:StreamAnalysisFacts 的最小投影(analyzeStream 输出;对照只消费降级标志)
 * - eventsX:事件数组 —— TcpEvent(M3)/ M5Event(M5)/ AppEvent(应用层)三源合一。
 *
 * **绝不跨侧合并字节/重组序列空间**:所有对比都在「已算好的结论」层面进行。
 *
 * 事件判定键 = kind + 归一化缺口区间。缺口区间四舍五入到整数再比较:
 * 两侧 tshark 对同一段数据给出的 raw 序号理论上同值,但文本格式(进制/宽度)可能不同,
 * 数字归一是唯一稳定口径;比较后展示用的 gapText 按侧各存(文本可不同)。
 */

// ---------------------------------------------------------------------------
// 窄接口(最小结构类型:TcpEvent / M5Event 均可结构赋值;多出的字段不妨碍兼容)
// ---------------------------------------------------------------------------

/** 事件窄接口。 TcpEvent 带 gap;M5 事件无 gap/recovered 字段(recovered 由 diff 按
 *  「是否已收束」推导);AppEvent 先归一成 keyed 事件再进同一比较空间。 */
export interface CompareTcpEvent {
  /** 事件类型:M3 三类(possible-loss-or-delay / reordering / possible-ack-loss-or-spurious)、
   *  M5 四类(zero-window / full-window / rst / syn-retransmission) */
  kind: string
  /** 缺口是否已被补齐(M3 事件原生携带;缺省视为无待恢复状态) */
  recovered?: boolean
  /** 缺口区间(判定键的一部分;M5 事件无缺口) */
  gap?: { start: number; end: number; byteCount: number }
}

/** 序列空间事实窄接口:对照层只消费降级标志(供结论措辞限定),不读序列细节。 */
export interface CompareFacts {
  /** 是否中途抓包(为真时流起始缺失不构成丢包证据,与单侧分析同一红线) */
  midStream: boolean
}

/** PacketDiffStats:每侧包数与字节数(diff 层只报两侧各自观察值,不算差值绝对数 ——
 *  差值由结论层解释,数字本身保持「各自观察事实」口径) */
export interface PacketDiffStats {
  countA: number
  countB: number
  bytesA: number
  bytesB: number
}

export interface EventDiffEntry {
  /** 事件类型(如 possible-loss-or-delay / zero-window / rst / http:request ...) */
  kind: string
  /** 缺口区间文本(判定键的一部分,两侧文本可不同;仅单侧存在时取该侧文本) */
  gapText?: string
  recovered: boolean
  onlyIn: 'A' | 'B' | 'both'
}

export interface TimelineRow {
  /** 对齐后的绝对秒(frame.time_epoch;两侧各自 relative 时间不可比) */
  timeEpoch: number
  /** 仅A见到 / 仅B见到 / 两侧均见 */
  side: 'A' | 'B' | 'AB'
  /** A 侧帧号(仅 B 见到时省略) */
  numberA?: number
  numberB?: number
  infoA?: string
  infoB?: string
}

export interface ConversationDiff {
  stats: PacketDiffStats
  eventDiffs: EventDiffEntry[]
  /** 按 timeEpoch 升序;AB 行 infoA!==infoB 时保留两者 */
  timeline: TimelineRow[]
  /** 时间线超过 2000 行被截断(防巨型会话撑爆 UI;截断保留最早 2000 行) */
  truncated: boolean
}

export interface DiffOptions {
  /** 同一交互两侧均见的 epoch 容差(毫秒),默认 2ms */
  epochToleranceMs?: number
}

/** 时间线行数上限:超过即截断(保最早行)。巨型会话(重传风暴)动辄数万包,
 *  全量渲染 HTML/UI 会卡死,与 aggregate 层「渲染上限」同一思路。 */
const TIMELINE_MAX_ROWS = 2000

/** 默认 epoch 容差:2ms。同链路两点抓包的转发延迟通常远小于 1ms,
 *  2ms 足以容忍时间戳精度差而不至于把不同报文误并(可在 opts 覆盖)。 */
const DEFAULT_EPOCH_TOLERANCE_MS = 2

// ---------------------------------------------------------------------------
// AppEvent 归一:应用层事件进入与 TCP 事件同一比较空间
// ---------------------------------------------------------------------------

/** AppEvent 的最小结构(避免整包 import 造成对照层对分析层模块图耦合加深) */
interface AppEventLike {
  app: 'http' | 'dns' | 'tls' | 'ssh' | 'rdp' | 'vnc' | 'smb'
  kind: 'request' | 'response' | 'query' | 'handshake' | 'session'
  summary: string
  packetNumber: number
}

interface NormalizedEvent {
  kind: string
  recovered: boolean
  gap?: { start: number; end: number; byteCount: number }
}

/** M5 事件形态:无 gap;收束报文 endPacket 存在 = 已收束(零窗口重开/SYN-ACK 到达)。
 *  rst / full-window 是点事件,无「待恢复」语义,按已收束处理。 */
interface M5EventLike {
  kind: 'zero-window' | 'full-window' | 'rst' | 'syn-retransmission'
  startPacket: number
  endPacket?: number
}

/** 事件守卫:unknown 收窄到已知事件形态(有 kind 字符串字段即可 ——
 *  TcpEvent / M5Event / AppEvent 三者均携带 kind;异形对象在 normalize 内再分流)。
 *  对照层对非法输入降级为「无事件」而不是抛错,报告导出应尽力而为。 */
function isKnownEventShape(e: unknown): e is CompareTcpEvent | M5EventLike | AppEventLike {
  return e != null && typeof e === 'object' && typeof (e as { kind?: unknown }).kind === 'string'
}

function normalizeEvent(e: CompareTcpEvent | M5EventLike | AppEventLike): NormalizedEvent {
  // AppEvent:无 app 字段的是 TCP 事件;有则是应用层事件,kind 合成 `${app}:${kind}`
  if ('app' in e) {
    return { kind: `${e.app}:${e.kind}`, recovered: true }
  }
  // M5 事件:kind 在 M5 集合内且无 gap 字段(CompareTcpEvent 理论上也可不带 gap,
  // 但 M5 的四种 kind 值与 M3 三类互斥,按 kind 集合判别是稳定口径)
  const isM5 =
    e.kind === 'zero-window' || e.kind === 'full-window' || e.kind === 'rst' || e.kind === 'syn-retransmission'
  if (isM5) {
    const m5 = e as M5EventLike
    // 点事件(rst/full-window)无待恢复状态;zero-window/syn-retransmission 以收束报文为准
    const recovered = m5.kind === 'rst' || m5.kind === 'full-window' ? true : m5.endPacket != null
    return { kind: m5.kind, recovered }
  }
  const tcp = e as CompareTcpEvent
  return { kind: tcp.kind, recovered: tcp.recovered ?? true, gap: tcp.gap }
}

// ---------------------------------------------------------------------------
// 判定键:kind + 归一化缺口区间(四舍五入到整数,避免两侧文本同值不同形)
// ---------------------------------------------------------------------------

function eventKey(e: NormalizedEvent): string {
  if (!e.gap) return e.kind
  // 四舍五入到整数:raw 序号本身是整数,小数只可能来自本测试/桥接层的合成值
  const s = Math.round(e.gap.start)
  const n = Math.round(e.gap.end)
  return `${e.kind}|${s}:${n}`
}

function gapTextOf(e: NormalizedEvent): string | undefined {
  if (!e.gap) return undefined
  return `${Math.round(e.gap.start)}–${Math.round(e.gap.end)}`
}

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

export function diffConversations(
  sideA: Conversation,
  factsA: unknown,
  eventsA: unknown[],
  sideB: Conversation,
  factsB: unknown,
  eventsB: unknown[],
  opts?: DiffOptions,
): ConversationDiff {
  // facts 只消费降级标志:参数保留 unknown 由内部窄化 —— 调用方传真实
  // StreamAnalysisFacts 或最小 { midStream } 均可,缺字段按「无降级」处理
  const factsAMid = midStreamOf(factsA)
  const factsBMid = midStreamOf(factsB)

  const stats: PacketDiffStats = {
    countA: sideA.packetCount,
    countB: sideB.packetCount,
    bytesA: sideA.bytes,
    bytesB: sideB.bytes,
  }

  // ---- 事件差异:判定键(归一化缺口 + recovered)相同的合并为 both ----
  // 入参按契约窄化:events 元素应为 CompareTcpEvent | M5Event | AppEvent 形态
  // (真实调用来自 detectTcpEvents / detect*M5Events / runApplicationAnalyzers 的输出),
  // 窄化失败(混入非法对象)按无事件处理而不是抛错 —— 对照报告应尽力而为
  const normA = eventsA.filter(isKnownEventShape).map(normalizeEvent)
  const normB = eventsB.filter(isKnownEventShape).map(normalizeEvent)
  const keyA = new Map<string, NormalizedEvent>()
  for (const e of normA) if (!keyA.has(eventKey(e))) keyA.set(eventKey(e), e)
  const keyB = new Map<string, NormalizedEvent>()
  for (const e of normB) if (!keyB.has(eventKey(e))) keyB.set(eventKey(e), e)

  const eventDiffs: EventDiffEntry[] = []
  const seenKeys = new Set<string>()
  for (const e of normA) {
    const k = eventKey(e)
    if (seenKeys.has(k)) continue // 同侧同键事件去重(判定键相同即同一现象)
    seenKeys.add(k)
    if (keyB.has(k)) {
      eventDiffs.push({ kind: e.kind, gapText: gapTextOf(e), recovered: e.recovered, onlyIn: 'both' })
    } else {
      eventDiffs.push({ kind: e.kind, gapText: gapTextOf(e), recovered: e.recovered, onlyIn: 'A' })
    }
  }
  for (const e of normB) {
    const k = eventKey(e)
    if (seenKeys.has(k)) continue
    seenKeys.add(k)
    eventDiffs.push({ kind: e.kind, gapText: gapTextOf(e), recovered: e.recovered, onlyIn: 'B' })
  }
  // 排序确定:仅单侧优先(对照最关心的差异)→ kind → 缺口文本
  eventDiffs.sort(
    (x, y) =>
      (x.onlyIn === 'both' ? 1 : 0) - (y.onlyIn === 'both' ? 1 : 0) ||
      x.kind.localeCompare(y.kind) ||
      (x.gapText ?? '').localeCompare(y.gapText ?? ''),
  )

  // ---- 时间线:两侧包按 time_epoch 归并,同侧互见(方向相反 + epoch 差 ≤ 容差)合并 AB 行 ----
  const timeline = buildTimeline(sideA.packets, sideB.packets, opts?.epochToleranceMs ?? DEFAULT_EPOCH_TOLERANCE_MS)

  // midStream 降级标志当前不改变差异计算(序列结论已在单侧分析内降级),
  // 读取它只为让调用方在报告层可统一判断两侧口径;此处显式引用防「未消费」误判
  void factsAMid
  void factsBMid

  return { stats, eventDiffs, timeline, truncated: timeline.length >= TIMELINE_MAX_ROWS }
}

function midStreamOf(facts: unknown): boolean {
  if (facts != null && typeof facts === 'object' && 'midStream' in facts) {
    return (facts as { midStream: unknown }).midStream === true
  }
  return false
}

/** 两侧报文按 epoch 归并:同侧互见 = 方向相反(一请求一响应)+ epoch 差 ≤ 容差。
 *  「两侧均见」指的是**同一交互的两侧视角**(A 抓到请求、B 抓到响应或反之),
 *  同方向两包即使 epoch 相邻也是不同报文(如 A 侧只见重传、B 侧见原始),不合并。 */
function buildTimeline(packetsA: Packet[], packetsB: Packet[], toleranceMs: number): TimelineRow[] {
  const tol = toleranceMs / 1000
  // epoch 缺失的报文:无法参与绝对时间对齐,退回 relative time(time 字段)。
  // 两侧 relative 基准不同,但缺 epoch 时这是唯一可排序的时间,如实降级并排序。
  const epochOf = (p: Packet): number => p.timeEpoch ?? p.time

  const aSorted = [...packetsA].sort((x, y) => epochOf(x) - epochOf(y) || x.number - y.number)
  const bSorted = [...packetsB].sort((x, y) => epochOf(x) - epochOf(y) || x.number - y.number)

  // AB 合并:对 A 的每包,在 B 的未合并包里找「方向相反 + epoch 差 ≤ tol」的最早者。
  // 两侧均已按时间排序,用双指针 + 已用标记,避免 O(n²):B 指针只前进(A 时间单调)。
  const bUsed = new Array<boolean>(bSorted.length).fill(false)
  let bi = 0
  const rows: TimelineRow[] = []
  for (const pa of aSorted) {
    const ta = epochOf(pa)
    // 推进 bi 跳过已不可能匹配的 B 包(epoch 差已超容差且 B 在前)
    while (bi < bSorted.length && (bUsed[bi] || epochOf(bSorted[bi]) < ta - tol)) bi++
    // 在 [bi, 第一个 epoch > ta+tol) 窗口内找方向相反的未用 B 包
    let match = -1
    for (let j = bi; j < bSorted.length; j++) {
      const tb = epochOf(bSorted[j])
      if (tb > ta + tol) break
      if (bUsed[j]) continue
      if (oppositeDirection(pa, bSorted[j])) {
        match = j
        break
      }
    }
    if (match >= 0) {
      bUsed[match] = true
      const pb = bSorted[match]
      rows.push({
        timeEpoch: ta, // 同一交互取 A 侧时刻(容差内的微差属时间戳精度,不承载信息)
        side: 'AB',
        numberA: pa.number,
        numberB: pb.number,
        infoA: pa.info,
        infoB: pb.info,
      })
    } else {
      rows.push({ timeEpoch: ta, side: 'A', numberA: pa.number, infoA: pa.info })
    }
  }
  // B 侧剩余未匹配包
  for (let j = 0; j < bSorted.length; j++) {
    if (bUsed[j]) continue
    const pb = bSorted[j]
    rows.push({ timeEpoch: epochOf(pb), side: 'B', numberB: pb.number, infoB: pb.info })
  }

  rows.sort(
    (x, y) =>
      x.timeEpoch - y.timeEpoch ||
      (x.numberA ?? x.numberB ?? 0) - (y.numberA ?? y.numberB ?? 0) ||
      x.side.localeCompare(y.side),
  )

  // 截断护栏:保留最早 2000 行,超限置 truncated(报告层标注「已截断」)
  if (rows.length > TIMELINE_MAX_ROWS) {
    return rows.slice(0, TIMELINE_MAX_ROWS)
  }
  return rows
}

/** 方向相反判定:按 Packet.direction(request/response)。'other' 方向(无法判向)不参与合并 ——
 *  把无法判向的报文并进「两侧均见」会伪造交互配对。 */
function oppositeDirection(a: Packet, b: Packet): boolean {
  if (a.direction === 'other' || b.direction === 'other') return false
  return a.direction !== b.direction
}
