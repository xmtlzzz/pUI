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
})
