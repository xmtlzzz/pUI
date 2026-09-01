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
  /** 流方向(TcpEvent 原生携带:c2s=客户端→服务端方向的数据流)。
   *  缺口事件的方向决定「丢失发生在哪条传输路径上」的推断方向 —— 接收侧是
   *  观察到缺口的侧,发送侧到观察侧之间是丢失可能发生的路径段 */
  direction?: 'c2s' | 's2c'
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
  /** 事件所在流方向(c2s=客户端→服务端;仅 TCP 事件携带)。
   *  结论层用它把「仅 X 侧观察到缺口」翻译成「数据从客户端流向服务端的路径上」
   *  等端点级措辞 —— 缺口的观察侧是接收侧,发送侧→接收侧之间是丢失候选路径段 */
  direction?: 'c2s' | 's2c'
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

/** 时钟偏移估计上限:两侧抓包首包 epoch 差超过该值即视为存在时钟偏移,
 *  启动「先对偏移再配对」的两阶段匹配(现网两端时钟不同步是常态)。 */
const SKEW_SUSPECT_S = 1.0

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
  direction?: 'c2s' | 's2c'
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
  return { kind: tcp.kind, recovered: tcp.recovered ?? true, gap: tcp.gap, direction: tcp.direction }
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
  const pushDiff = (e: NormalizedEvent, onlyIn: 'A' | 'B' | 'both'): void => {
    eventDiffs.push({ kind: e.kind, gapText: gapTextOf(e), recovered: e.recovered, onlyIn, direction: e.direction })
  }
  for (const e of normA) {
    const k = eventKey(e)
    if (seenKeys.has(k)) continue // 同侧同键事件去重(判定键相同即同一现象)
    seenKeys.add(k)
    pushDiff(e, keyB.has(k) ? 'both' : 'A')
  }
  for (const e of normB) {
    const k = eventKey(e)
    if (seenKeys.has(k)) continue
    seenKeys.add(k)
    pushDiff(e, 'B')
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

/** 两侧报文按 epoch 归并,两级配对:
 *
 *  通道 1(物理包身份):同一物理包两侧都会见到 —— TCP 用「同方向 + seq/ack/flags/
 *  载荷长一致」,其余协议用「同方向 + 载荷长一致」;配对时先估计时钟偏移(B 首包 -
 *  A 首包,|偏移| > 1s 视为偏移嫌疑),对齐后 epoch 差 ≤ 容差即合并 AB 行。
 *  这是「同一个包两点都看见」的正确判定 —— 方向相同的同 seq 包在 A、B 各出现一次,
 *  旧实现按「方向相反」配对,时钟偏移 > 容差时全部行退化为仅A/仅B,时间线不可读。
 *
 *  通道 2(交互配对):无法用身份配对时,「方向相反 + 对齐后 epoch 差 ≤ 容差」
 *  合并为同一交互的两侧视角(如 A 抓到响应、B 抓到同一响应:某些观测点只见单向)。
 *
 *  丢失段在接收侧没有对应包 → 自然留在「仅发送侧」行,这正是定位证据行。 */
function buildTimeline(packetsA: Packet[], packetsB: Packet[], toleranceMs: number): TimelineRow[] {
  const tol = toleranceMs / 1000
  // epoch 缺失的报文:无法参与绝对时间对齐,退回 relative time(time 字段)。
  // 两侧 relative 基准不同,但缺 epoch 时这是唯一可排序的时间,如实降级并排序。
  const epochOf = (p: Packet): number => p.timeEpoch ?? p.time

  const aSorted = [...packetsA].sort((x, y) => epochOf(x) - epochOf(y) || x.number - y.number)
  const bSorted = [...packetsB].sort((x, y) => epochOf(x) - epochOf(y) || x.number - y.number)

  // 时钟偏移估计:B 侧首包 epoch − A 侧首包 epoch(会话起点近似同物理时刻:
  // TCP 三次握手的 SYN 两侧几乎必见,其 epoch 差即偏移)。仅当差值可疑(>1s)时启用
  // 补偿;正常同步时钟下偏移 ≈ 转发延迟,补偿与否等价。
  let skew = 0
  if (aSorted.length > 0 && bSorted.length > 0) {
    const rawSkew = epochOf(bSorted[0]) - epochOf(aSorted[0])
    if (Math.abs(rawSkew) > SKEW_SUSPECT_S) skew = rawSkew
  }
  // 对齐函数:B 侧时间减去偏移 → A 时基
  const alignB = (p: Packet): number => epochOf(p) - skew

  // 通道 1:物理包身份(A 每个 B 未用包里找同身份 + 对齐后差 ≤ tol)
  const identityOf = (p: Packet): string => {
    const seq = p.tcpSeq != null ? `,seq=${p.tcpSeq}` : ''
    const len = p.tcpLen != null ? `,len=${p.tcpLen}` : ''
    const flags = p.tcpFlags != null ? `,f=${p.tcpFlags}` : ''
    const ack = p.tcpAck != null ? `,ack=${p.tcpAck}` : ''
    return p.transport === 'tcp'
      ? `${p.direction}|${p.srcIp}<${p.srcPort}>-${p.dstIp}<${p.dstPort}>${seq}${ack}${flags}${len}`
    : `${p.srcIp}-${p.dstIp}${seq}${len}`
  }
  const bIdentities = new Map<string, number[]>() // 身份 → B 下标列表(同 seq 重传可多包)
  bSorted.forEach((p, i) => {
    const k = identityOf(p)
    const arr = bIdentities.get(k)
    if (arr) arr.push(i)
    else bIdentities.set(k, [i])
  })

  const bUsed = new Array<boolean>(bSorted.length).fill(false)
  // 通道 2 用双指针:A 按时间单调推进,B 指针只前进(跳过已用/已过期),整体 O(n+m)。
  // 通道 1 的身份匹配对每包只扫「同身份」短列表,不影响总复杂度。
  let scanStart = 0
  const rows: TimelineRow[] = []
  for (const pa of aSorted) {
    const ta = epochOf(pa)
    // 通道 1:同身份且对齐后差 ≤ tol 的最早未用 B 包
    let match = -1
    for (const j of bIdentities.get(identityOf(pa)) ?? []) {
      if (bUsed[j]) continue
      if (Math.abs(alignB(bSorted[j]) - ta) <= tol) {
        match = j
        break
      }
    }
    // 通道 2:交互配对(方向相反 + 对齐后差 ≤ tol,取最早);B 指针单调推进
    if (match < 0) {
      while (scanStart < bSorted.length && (bUsed[scanStart] || alignB(bSorted[scanStart]) < ta - tol)) scanStart++
      for (let j = scanStart; j < bSorted.length; j++) {
        const tb = alignB(bSorted[j])
        if (tb > ta + tol) break
        if (bUsed[j]) continue
        if (oppositeDirection(pa, bSorted[j])) {
          match = j
          break
        }
      }
    }
    if (match >= 0) {
      bUsed[match] = true
      const pb = bSorted[match]
      rows.push({
        timeEpoch: ta, // 同一包/同一交互取 A 侧时刻(时钟偏移已在配对中补偿)
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
