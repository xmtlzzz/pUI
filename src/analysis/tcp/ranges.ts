import { SEQ_SPACE, seqDiff } from './seq'

/** 半开区间 [start, end),坐标为"展开后"的单调序列空间(见下方说明) */
type Range = [number, number]

/**
 * 序列空间区间集合:记录某个方向上"哪些字节已经见过"。
 *
 * ## 为什么内部不直接用 32 位序列号
 *
 * 32 位序列号会在 2^32 处回绕,若直接存原始值,一个跨回绕的连续段会变成
 * [4294967200, 4294967295] 和 [0, 104] 两段看似不相邻的区间,合并逻辑会把它们之间
 * 当成空洞 —— 正好是"凭空造 Gap"这类假阳性。
 *
 * 因此内部把序列号展开(unwrap)到单调递增的绝对坐标:以首个观察到的序列号为原点,
 * 每个新序列号按与上一次参考点的有符号差值累加。JS number 可精确表示到 2^53,
 * 足够容纳任何真实抓包时长内的累计字节数(2^53 字节 ≈ 9PB),不会精度丢失。
 *
 * 复杂度:add 用二分定位插入点,均摊 O(log k);k 为当前不连续区间数,顺序流下 k=1。
 * 不做全量重排,不复制报文。
 */
export class SeqRanges {
  /** 已见区间,按 start 升序、互不相交、互不相邻(相邻即合并) */
  private ranges: Range[] = []
  /** 展开坐标的原点(首个观察到的 32 位序列号) */
  private origin: number | null = null
  /** 上一次展开时的参考点(32 位),用于判断回绕方向 */
  private lastRaw = 0
  /** 上一次展开得到的绝对坐标 */
  private lastAbs = 0

  /**
   * 把 32 位序列号展开为单调绝对坐标。
   * 依赖"相邻观察值之间的跨度远小于 2^31"这一 TCP 事实:据有符号差值决定前进/后退,
   * 因此回绕(小值跟在大值之后)会被正确识别为前进而非后退 2^32。
   */
  private unwrap(seq: number): number {
    const s = seq >>> 0
    if (this.origin === null) {
      this.origin = s
      this.lastRaw = s
      this.lastAbs = 0
      return 0
    }
    const abs = this.lastAbs + seqDiff(s, this.lastRaw)
    this.lastRaw = s
    this.lastAbs = abs
    return abs
  }

  /** 把绝对坐标折回 32 位序列号,供对外输出 */
  private wrap(abs: number): number {
    const o = this.origin ?? 0
    // abs 可能为负(早于原点的数据),先取模再归一到 [0, 2^32)
    const m = ((o + abs) % SEQ_SPACE + SEQ_SPACE) % SEQ_SPACE
    return m
  }

  /** 加入一段已见字节 [start, end)。零长度(纯 ACK/keep-alive)不占序列空间,忽略。 */
  add(start: number, end: number): void {
    const a = this.unwrap(start)
    // end 用与 start 相同的参考展开,避免 end 单独展开时把长度算成负数
    const len = seqDiff(end >>> 0, start >>> 0)
    if (len <= 0) return // 零长度或异常(end 在 start 之前)
    this.insert(a, a + len)
  }

  private insert(a: number, b: number): void {
    const rs = this.ranges
    // 二分找到第一个 end >= a 的区间(它可能与新区间相邻或重叠)
    let lo = 0
    let hi = rs.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (rs[mid][1] < a) lo = mid + 1
      else hi = mid
    }
    let i = lo
    let ns = a
    let ne = b
    // 吞掉所有与 [ns,ne] 相接/重叠的区间
    let j = i
    while (j < rs.length && rs[j][0] <= ne) {
      ns = Math.min(ns, rs[j][0])
      ne = Math.max(ne, rs[j][1])
      j++
    }
    rs.splice(i, j - i, [ns, ne])
  }

  isEmpty(): boolean {
    return this.ranges.length === 0
  }

  /** [start, end) 是否已被完整覆盖 */
  covers(start: number, end: number): boolean {
    const len = seqDiff(end >>> 0, start >>> 0)
    if (len <= 0) return false
    const a = this.absOf(start)
    if (a === null) return false
    const b = a + len
    for (const [s, e] of this.ranges) {
      if (s <= a && b <= e) return true
      if (s > a) break
    }
    return false
  }

  /** [start, end) 中尚未见过的字节数 */
  newBytes(start: number, end: number): number {
    const len = seqDiff(end >>> 0, start >>> 0)
    if (len <= 0) return 0
    const a = this.absOf(start)
    if (a === null) return len // 尚无任何数据 → 全新
    const b = a + len
    let seen = 0
    for (const [s, e] of this.ranges) {
      if (e <= a) continue
      if (s >= b) break
      seen += Math.min(e, b) - Math.max(s, a)
    }
    return len - seen
  }

  /**
   * 把 32 位序列号映射到绝对坐标,但不推进展开参考点(查询不应有副作用)。
   * 以当前参考点为基准做有符号差值。
   */
  private absOf(seq: number): number | null {
    if (this.origin === null) return null
    return this.lastAbs + seqDiff(seq >>> 0, this.lastRaw)
  }

  /** 当前存在的空洞(已见区间之间的缺口),按序列顺序返回 32 位边界 */
  gaps(): Array<[number, number]> {
    const out: Array<[number, number]> = []
    for (let i = 1; i < this.ranges.length; i++) {
      out.push([this.wrap(this.ranges[i - 1][1]), this.wrap(this.ranges[i][0])])
    }
    return out
  }

  /** 已见字节总数 */
  totalBytes(): number {
    let n = 0
    for (const [s, e] of this.ranges) n += e - s
    return n
  }

  /** 已见区间(32 位边界),按序列顺序 */
  toArray(): Array<[number, number]> {
    return this.ranges.map(([s, e]) => [this.wrap(s), this.wrap(e)] as [number, number])
  }

  /** 已见数据的最高边界(下一个期望字节),空集时为 undefined */
  highest(): number | undefined {
    if (!this.ranges.length) return undefined
    return this.wrap(this.ranges[this.ranges.length - 1][1])
  }
}
