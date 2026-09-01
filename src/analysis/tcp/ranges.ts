import { SEQ_SPACE, seqDiff } from './seq'

/** 可信带向前余量:新段领先已见前沿(maxEnd)的最大可信距离(字节)。 */
const FWD_MARGIN = 0x6000_0000 // 1.5GiB

/** 可信带向后余量:迟到/重传段允许落后已见数据起点(minStart)多远。
 *
 *  下界由两个互斥的既有事实要求夹出,取中值:
 *  - 必须接纳:真实长传输跨回绕后的补填段,近侧读数会呈现为落后约 1.29e9
 *    (既有用例:add(1,101) 后 add(3e9,...)),小于该值会丢真实数据;
 *  - 必须拒绝:外来 ISN(相距 2.5e9)的近侧读数呈现为落后约 1.79e9,
 *    放宽到带内会把拼接抓包误判成"迟到补填",造出十亿字节级幻影空洞。
 *  向前余量取同值保持对称:两个方向各自留出 <2^31 的物理不可能区,
 *  相邻候选间隔恰为 2^32,故带内最多容纳两个候选,歧义可按"距跨度最近"裁决。 */
const BACK_MARGIN = 0x6000_0000 // 1.5GiB

/** 半开区间 [start, end),坐标为"展开后"的单调序列空间(见下方说明) */
type Range = [number, number]

/** 空洞及其绝对坐标:绝对坐标是跨回绕流排序的唯一可靠键 */
export interface GapWithAbs {
  start: number
  end: number
  startAbs: number
  endAbs: number
}

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
  /** 已见字节总数(增量维护;totalBytes() O(1) 读取。VDI 级大会话
   *  analyzeStream 每包要读两次,逐区间求和的 O(k) 会变成 O(n·k) 冻结主线程) */
  private total = 0
  /** 空洞数量(增量维护;区间数 k 的空洞恒为 k-1,直接由区间数导出) */
  private gapTotal = 0
  /** 最近一次 insert 合并后新区间的下标(insert 局部性:每包只影响 O(1) 个洞) */
  private lastTouched = 0
  /** 展开坐标的原点(首个观察到的 32 位序列号) */
  private origin: number | null = null
  /** 上一次展开时的参考点(32 位),用于判断回绕方向 */
  private lastRaw = 0
  /** 上一次展开得到的绝对坐标 */
  private lastAbs = 0
  /** 是否遇到过无法定序的输入(相距 ≥2^31),需由分析层降级为限制说明 */
  private unorderableInput = false

  /**
   * 候选带放置:把 32 位序列号唯一地映射到单调绝对坐标。
   *
   *  环上近侧读数 c = lastAbs + seqDiff(s, lastRaw) 只是一个**假设**,不是事实:
   *  参考点被后续报文推进后,用旧序列号查询会落到环的错误一侧(实测:推进 3GB 后
   *  covers(0,100)=false、newBytes(0,100)=100)。因此读数连同 ±2^32 的两个候选
   *  一起参与判定,只有落入可信带的候选才被采信:
   *
   *      [ minStart - BACK_MARGIN , maxEnd + FWD_MARGIN ]
   *
   *  已见数据必然落带内(不会"丢出带外");远超物理可能的偏移(外来 ISN)
   *  则三个候选全部落空而被拒绝。
   *
   *  多候选入带在跨度超过 2^32-余量之和(约 2.79GB)的长流上真实出现(跨回绕处
   *  必然如此),裁决分两步,只对 add 生效(len>0 且 advance):
   *  1) 纯重复剔除:与已见字节完全重合(零新字节)的候选是"同一份数据"而非新事实,
   *     若存在非重复候选则剔除之 —— 否则跨回绕后的延续段会被误并回环上旧位置,
     *     整条流的后续全部塌缩(实测 24 段跨回绕流只余 15 个空洞);
   *  2) 类内择近:跨度内部 > 前沿之外(前进延续先验)> 起点之前;
   *     同类取距跨度最近者,同距取更大(更靠前)候选 —— 结果确定且偏向前进。
   *
   *  - add 路径:无候选入带 → 拒绝并置不可定序标记;
   *  - 查询路径:无副作用(不推进参考点、不改标记),带外时退回近侧读数兜底,
   *    多候选时直接按类内择近(查询的"完全重合"候选恰恰是正确答案,不剔除)。
   */
  private place(seq: number, len: number, advance: boolean): number | null {
    const s = seq >>> 0
    if (this.origin === null) {
      if (!advance) return null
      this.origin = s
      this.lastRaw = s
      this.lastAbs = 0
      return 0
    }
    const near = this.lastAbs + seqDiff(s, this.lastRaw)
    // 已见数据的绝对跨度;可信带锚定在它的两端
    const rs = this.ranges
    const minStart = rs.length ? rs[0][0] : this.lastAbs
    const maxEnd = rs.length ? rs[rs.length - 1][1] : this.lastAbs
    const bandLo = minStart - BACK_MARGIN
    const bandHi = maxEnd + FWD_MARGIN
    const cands: number[] = []
    for (const c of [near - SEQ_SPACE, near, near + SEQ_SPACE]) {
      if (c >= bandLo && c <= bandHi) cands.push(c)
    }
    if (cands.length === 0) {
      if (advance) {
        this.unorderableInput = true
        return null // add 路径:无可信落点 → 拒绝(null 由 add 转为 false)
      }
      return near // 查询路径兜底:带外输入保持旧语义的近侧读数
    }
    let pool = cands
    if (advance && cands.length > 1) {
      const useful = cands.filter((c) => !this.fullySeen(c, c + len))
      if (useful.length > 0) pool = useful
    }
    // 类内择近(见上方说明)
    const clsOf = (c: number): number => (c >= minStart && c <= maxEnd ? 0 : c > maxEnd ? 1 : 2)
    const distTo = (c: number): number => (c < minStart ? minStart - c : c > maxEnd ? c - maxEnd : 0)
    let best = pool[0]
    for (const c of pool) {
      const kc = clsOf(c)
      const kb = clsOf(best)
      if (kc !== kb) {
        if (kc < kb) best = c
        continue
      }
      const dc = distTo(c)
      const db = distTo(best)
      if (dc < db || (dc === db && c > best)) best = c
    }
    if (!advance) return best // 查询路径到此为止:不推进参考点
    this.lastAbs = best
    this.lastRaw = s
    return best
  }

  /** [a,b) 是否已被已见区间完整覆盖(用于识别纯重复候选) */
  private fullySeen(a: number, b: number): boolean {
    const rs = this.ranges
    let lo = 0
    let hi = rs.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (rs[mid][1] < a) lo = mid + 1
      else hi = mid
    }
    let cursor = a
    for (let i = lo; i < rs.length && rs[i][0] < b; i++) {
      if (rs[i][0] > cursor) return false
      if (rs[i][1] > cursor) cursor = rs[i][1]
      if (cursor >= b) return true
    }
    return cursor >= b
  }

  /** 把 32 位序列号展开为单调绝对坐标(add 路径,允许推进参考点并拒绝脏输入) */
  private unwrap(seq: number, len: number): number | null {
    return this.place(seq, len, true)
  }

  /** 把绝对坐标折回 32 位序列号,供对外输出 */
  private wrap(abs: number): number {
    const o = this.origin ?? 0
    // abs 可能为负(早于原点的数据),先取模再归一到 [0, 2^32)
    const m = ((o + abs) % SEQ_SPACE + SEQ_SPACE) % SEQ_SPACE
    return m
  }

  /** 加入一段已见字节 [start, end)。零长度(纯 ACK/keep-alive)不占序列空间,忽略。
   *
   *  返回是否被接纳。候选带放置(place)找不到可信落点时拒绝并置不可定序标记:
   *  这种偏移在真实 TCP 中不可能出现,强行接纳会造出十亿字节级的幻影空洞。
   *  对一个"不许过度推断"的分析工具,拒绝并如实标注远比猜一侧正确。 */
  add(start: number, end: number): boolean {
    const len = seqDiff(end >>> 0, start >>> 0)
    if (len <= 0) return false // 零长度或异常(end 在 start 之前)
    const a = this.unwrap(start, len)
    if (a === null) return false
    this.insert(a, a + len)
    return true
  }

  /** 是否出现过无法定序的输入(供分析层降级为 limitation,而不是当作事实) */
  hasUnorderableInput(): boolean {
    return this.unorderableInput
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
    // 增量维护字节总数:合并后区间长 - 被吞区间总长 = 净增
    let eaten = 0
    for (let k = i; k < j; k++) eaten += rs[k][1] - rs[k][0]
    this.total += (ne - ns) - eaten
    rs.splice(i, j - i, [ns, ne])
    // 空洞数 = 区间数 - 1(区间有序互不重叠,相邻对之间恰为一个洞)
    this.gapTotal = Math.max(0, rs.length - 1)
    // 记录本次 insert 触及的内部区间下标范围(合并后的单一区间下标),
    // 供增量空洞对账只检查受影响的洞,而不是每包全量重建
    this.lastTouched = i
  }

  /** 最近一次 insert 合并后新区间在 ranges 中的下标(增量对账用) */
  lastTouchedIndex(): number {
    return this.lastTouched
  }

  isEmpty(): boolean {
    return this.ranges.length === 0
  }

  /** [start, end) 是否已被完整覆盖 */
  covers(start: number, end: number): boolean {
    const len = seqDiff(end >>> 0, start >>> 0)
    if (len <= 0) return false
    const a = this.absOf(start, len)
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
    const a = this.absOf(start, len)
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
   * 与 add 共用同一套候选带判定(但不做纯重复剔除 —— 查询语义是"按已存数据
   * 最一致地解释",与 add 的"优先解释为前进"刻意不同);带外时退回近侧读数兜底。
   */
  private absOf(seq: number, len: number): number | null {
    return this.place(seq, len, false)
  }

  /** 当前存在的空洞(已见区间之间的缺口),按序列顺序返回 32 位边界 */
  gaps(): Array<[number, number]> {
    return this.gapsWithAbs().map((g) => [g.start, g.end])
  }

  /** 空洞数量(O(1):insert 时增量维护)。analyzeStream 每包读一次,
   *  逐洞重建数组再取 length 的 O(k) 在高缺口率大会话下是秒级热点 */
  gapCount(): number {
    return this.gapTotal
  }

  /** 空洞及其绝对坐标:绝对坐标是跨回绕流排序的唯一可靠键。
   *  32 位边界在回绕后不保序(0 < 4294967200 但环上在前),跨回绕的多个空洞
   *  若按 32 位值排序会把"回绕之后"的洞排到最前 —— 上层据此会颠倒故障因果。
   *  ranges 本身按绝对坐标升序维护,故 startAbs 沿数组严格递增,与插入顺序无关。 */
  gapsWithAbs(): GapWithAbs[] {
    const out: GapWithAbs[] = []
    for (let i = 1; i < this.ranges.length; i++) {
      out.push({
        start: this.wrap(this.ranges[i - 1][1]),
        end: this.wrap(this.ranges[i][0]),
        startAbs: this.ranges[i - 1][1],
        endAbs: this.ranges[i][0],
      })
    }
    return out
  }

  /** 已见字节总数(O(1):insert 时增量维护) */
  totalBytes(): number {
    return this.total
  }

  /** 内部区间数(只读访问器,供增量空洞对账按下标遍历,免全量分配) */
  get rangeCount(): number {
    return this.ranges.length
  }

  /** 第 i 个内部区间(绝对坐标,只读)。i 必须在 [0, rangeCount) 内 */
  rangeAt(i: number): readonly [number, number] {
    return this.ranges[i]
  }

  /** 绝对坐标 → 32 位序列号(只读包装,供增量空洞对账把区间端点折回 32 位) */
  wrapOf(abs: number): number {
    return this.wrap(abs)
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
