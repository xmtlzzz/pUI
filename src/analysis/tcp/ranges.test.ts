import { describe, expect, it } from 'vitest'
import { SeqRanges } from './ranges'

/**
 * 序列空间区间集合:记录"哪些字节已经见过",并据此判断新到达的段是
 * 新数据 / 重复 / 部分重叠,以及当前存在哪些空洞。
 * 区间一律用半开区间 [start, end),与 TCP 序列号语义一致(end 即下一个期望字节)。
 */
describe('SeqRanges 区间集合', () => {
  it('新建时为空,无覆盖', () => {
    const r = new SeqRanges()
    expect(r.isEmpty()).toBe(true)
    expect(r.covers(100, 200)).toBe(false)
    expect(r.toArray()).toEqual([])
  })

  it('加入单个区间后可查询覆盖', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    expect(r.covers(100, 200)).toBe(true)
    expect(r.covers(120, 180)).toBe(true) // 子区间
    expect(r.covers(100, 201)).toBe(false) // 超出右界
    expect(r.covers(99, 200)).toBe(false) // 超出左界
    expect(r.toArray()).toEqual([[100, 200]])
  })

  it('零长度区间被忽略(纯 ACK/keep-alive 不占序列空间)', () => {
    const r = new SeqRanges()
    r.add(100, 100)
    expect(r.isEmpty()).toBe(true)
  })

  it('相邻区间合并为一个', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(200, 300) // 紧邻
    expect(r.toArray()).toEqual([[100, 300]])
  })

  it('重叠区间合并', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(150, 250)
    expect(r.toArray()).toEqual([[100, 250]])
  })

  it('乱序加入仍保持有序且合并', () => {
    const r = new SeqRanges()
    r.add(300, 400)
    r.add(100, 200)
    r.add(200, 300) // 把两段接起来
    expect(r.toArray()).toEqual([[100, 400]])
  })

  it('不相邻区间保持分离', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(300, 400)
    expect(r.toArray()).toEqual([
      [100, 200],
      [300, 400],
    ])
  })

  it('完全重复加入不改变集合', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(100, 200)
    expect(r.toArray()).toEqual([[100, 200]])
  })

  it('missingBetween 给出两个已见区间之间的空洞', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(300, 400)
    expect(r.gaps()).toEqual([[200, 300]])
  })

  it('多个空洞按序列顺序返回', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(300, 400)
    r.add(500, 600)
    expect(r.gaps()).toEqual([
      [200, 300],
      [400, 500],
    ])
  })

  it('空洞被填补后消失', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(300, 400)
    expect(r.gaps()).toHaveLength(1)
    r.add(200, 300)
    expect(r.gaps()).toEqual([])
    expect(r.toArray()).toEqual([[100, 400]])
  })

  it('newBytes 报告某段中尚未见过的字节数', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    expect(r.newBytes(100, 200)).toBe(0) // 完全重复
    expect(r.newBytes(200, 300)).toBe(100) // 全新
    expect(r.newBytes(150, 250)).toBe(50) // 部分重叠
    expect(r.newBytes(50, 150)).toBe(50) // 左侧部分重叠
  })

  it('跨 2^32 回绕的区间正确处理', () => {
    const r = new SeqRanges()
    // 4294967200 .. 回绕 .. 104
    r.add(4294967200, 4294967295)
    r.add(4294967295, 104) // 跨越回绕点
    // 两段应合并为一段连续数据(共 96 + 105 = 201 字节)
    expect(r.totalBytes()).toBe(4294967295 - 4294967200 + 105)
  })

  it('回绕处的连续段不被误判为空洞', () => {
    const r = new SeqRanges()
    r.add(4294967200, 4294967296 % 4294967296) // 到回绕点
    r.add(0, 104)
    expect(r.gaps()).toEqual([])
  })

  it('totalBytes 统计已见字节总数', () => {
    const r = new SeqRanges()
    r.add(100, 200)
    r.add(300, 400)
    expect(r.totalBytes()).toBe(200)
  })

  it('大量顺序段插入保持线性行为(性能护栏)', () => {
    const r = new SeqRanges()
    for (let i = 0; i < 20000; i++) r.add(i * 100, (i + 1) * 100)
    // 全部相邻 → 合并成一段
    expect(r.toArray()).toHaveLength(1)
    expect(r.gaps()).toEqual([])
  })

  it('相距达到半空间(无法定序)的段被拒绝,不产生幻影空洞', () => {
    // RFC 1982 下相距 ≥2^31 的两个序列号无法定序,无法判断新段在环的哪一侧。
    // 真实 TCP 流不会出现(需一次跳过 2GB 未确认数据),拼接抓包/ISN 突变才会;
    // 此时"拒绝并标记输入不可定序"远比"猜一侧"正确 —— 猜错会造出十亿字节级的假缺失。
    const r = new SeqRanges()
    r.add(1, 101)
    expect(r.add(0x8000_0000 + 1, 0x8000_0000 + 101)).toBe(false)
    expect(r.hasUnorderableInput()).toBe(true)
    expect(r.gaps()).toEqual([])
    expect(r.totalBytes()).toBe(100) // 只保留可信的那一段
  })

  it('可定序的大跨度段仍被接纳,并如实报出其间空洞', () => {
    // 距离虽大但 < 2^31,仍可定序 —— 这种情况必须如实反映,不能一并拒绝
    const r = new SeqRanges()
    r.add(1, 101)
    expect(r.add(3000000000, 3000000100)).toBe(true)
    expect(r.hasUnorderableInput()).toBe(false)
    expect(r.totalBytes()).toBe(200)
    expect(r.covers(1, 101)).toBe(true)
    // 空洞确实存在(1 亿+ 字节),如实报出;是否可信由上层结合抓包限制判断
    expect(r.gaps()).toHaveLength(1)
  })
})

/**
 * 候选带放置(candidate-band placement):
 * 展开不再只信环上"近侧读数",而是把读数连同 ±2^32 的两个候选一起,
 * 放进由已见数据跨度决定的可信带内择优;带外即拒绝。
 * 目标:既不因外来 ISN 造出十亿字节级幻影空洞,也不丢弃长传输中落后前沿很远的真实补填。
 */
describe('候选带放置:幻影空洞与迟到补填', () => {
  it('外来 ISN(相距 2.5e9)被拒绝,不制造幻影空洞', () => {
    const r = new SeqRanges()
    expect(r.add(1000, 1100)).toBe(true)
    expect(r.add(1100, 1200)).toBe(true)
    // 近侧读数把该段判为落后尾缘约 1.79e9 字节 —— 真实补填不可能落后这么多
    expect(r.add(2_500_000_000, 2_500_001_000)).toBe(false)
    expect(r.hasUnorderableInput()).toBe(true)
    expect(r.gaps()).toEqual([])
    expect(r.totalBytes()).toBe(200) // 只保留可信数据
  })

  it('长传输中落后前沿 1.29GB 的迟到补填仍被接纳并正确合并', () => {
    const r = new SeqRanges()
    r.add(1000, 1100)
    r.add(1200, 1300)
    expect(r.add(1_000_000_000, 1_000_000_100)).toBe(true)
    expect(r.add(2_000_000_000, 2_000_000_100)).toBe(true)
    expect(r.add(3_000_000_000, 3_000_000_100)).toBe(true)
    // 补填 [1100,1200):相对当前参考点(raw 3e9)的近侧读数是"前方 1.29e9",
    // 但它的另一候选恰落在已见数据内部 —— 必须按内部候选放置并合并三段
    expect(r.add(1100, 1200)).toBe(true)
    expect(r.hasUnorderableInput()).toBe(false)
    expect(r.totalBytes()).toBe(600) // 不重复字节恰好各计一次
    expect(r.toArray()[0]).toEqual([1000, 1300])
  })

  it('累计推进超过 2^31 后,查询旧数据不再落到环的错误一侧', () => {
    const r = new SeqRanges()
    r.add(0, 100)
    r.add(1_000_000_000, 1_000_000_100)
    r.add(2_000_000_000, 2_000_000_100)
    r.add(3_000_000_000, 3_000_000_100)
    expect(r.covers(0, 100)).toBe(true)
    expect(r.newBytes(0, 100)).toBe(0)
    // 全新区域照常报告
    expect(r.newBytes(3_000_000_100, 3_000_000_200)).toBe(100)
    // 查询无副作用:之后的新增仍按前进处理,而不是被查询带偏
    expect(r.add(3_000_000_300, 3_000_000_400)).toBe(true)
    expect(r.toArray()).toHaveLength(5)
  })

  it('跨度极大导致两个候选同落带内时,取距跨度最近者', () => {
    const r = new SeqRanges()
    // 建出约 2e9 字节的跨度(每跳 1e8,均远小于 2^31)
    for (let s = 0; s < 2_000_000_000; s += 100_000_000) r.add(s, s + 100)
    // raw 3e9 的两个候选(前移至 3e9 / 后退至 -1.29e9)都落在可信带内:
    // 距跨度最近的是 3e9(约 1e9),后退候选约 1.29e9 —— 应取前者
    expect(r.add(3_000_000_000, 3_000_000_100)).toBe(true)
    const arr = r.toArray()
    expect(arr[arr.length - 1]).toEqual([3_000_000_000, 3_000_000_100])
    expect(r.totalBytes()).toBe(2_000_000_000 / 100_000_000 * 100 + 100)
  })
})

describe('gapsWithAbs:跨回绕的绝对坐标空洞', () => {
  // 三段跨越回绕点、中间留两个洞:[0xffffff00,2^32) [0x200,0x300) [0x400,0x500)
  const SEGS: Array<[number, number]> = [
    [0xffff_ff00, 0x1_0000_0000],
    [0x0000_0200, 0x0000_0300],
    [0x0000_0400, 0x0000_0500],
  ]
  const build = (order: Array<[number, number]>): SeqRanges => {
    const r = new SeqRanges()
    for (const [s, e] of order) expect(r.add(s, e)).toBe(true)
    return r
  }

  it('任意插入顺序下 startAbs 沿数组严格递增,32 位视图与插入顺序无关', () => {
    const orders = [SEGS, [...SEGS].reverse(), [SEGS[2], SEGS[0], SEGS[1]]]
    const wrappedPerOrder = orders.map((o) => build(o).gapsWithAbs())
    for (const gs of wrappedPerOrder) {
      expect(gs).toHaveLength(2)
      for (let i = 1; i < gs.length; i++) {
        expect(gs[i].startAbs).toBeGreaterThan(gs[i - 1].startAbs)
        expect(gs[i].endAbs).toBeGreaterThan(gs[i - 1].endAbs)
      }
    }
    // 绝对坐标的原点取决于首见段,但折回 32 位后的视图必须一致
    const views = wrappedPerOrder.map((gs) => gs.map((g) => [g.start, g.end]))
    expect(views[1]).toEqual(views[0])
    expect(views[2]).toEqual(views[0])
    // 两个洞:回绕前一个 [0, 0x200),回绕后一个 [0x300, 0x400)
    expect(views[0]).toEqual([
      [0, 0x200],
      [0x300, 0x400],
    ])
  })

  it('gaps() 与 gapsWithAbs() 的 32 位边界一致', () => {
    const r = build(SEGS)
    expect(r.gaps()).toEqual(r.gapsWithAbs().map((g) => [g.start, g.end]))
  })

  it('totalBytes() 恒等于区间长度求和(增量维护与逐区间求和一致)', () => {
    // 乱序插入/重叠/相邻合并混合,验证增量计数不被合并逻辑算错
    const r = new SeqRanges()
    const expectSum = (r: SeqRanges): number => r.toArray().reduce((acc, [s, e]) => acc + (e - s), 0)
    r.add(1000, 2000)
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(3000, 4000) // 不相邻
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(2000, 3000) // 桥接合并两段
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(500, 1200) // 左侧重叠
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(3500, 4500) // 右侧重叠
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(1500, 1600) // 纯重复(零新增)
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(0, 0) // 零长度忽略
    expect(r.totalBytes()).toBe(expectSum(r))
    r.add(2000, 2500) // 落在已见区间内部
    expect(r.totalBytes()).toBe(expectSum(r))
  })

  it('大数据量下 totalBytes() 仍 O(1) 语义(结果与全求和一致)', () => {
    const r = new SeqRanges()
    for (let i = 0; i < 10000; i++) r.add(i * 10, i * 10 + 10)
    const sum = r.toArray().reduce((acc, [s, e]) => acc + (e - s), 0)
    expect(r.totalBytes()).toBe(sum)
    expect(sum).toBe(100000)
  })
})
