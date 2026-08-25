import { describe, expect, it } from 'vitest'
import { seqAdd, seqCmp, seqDiff, seqGt, seqGte, seqLt, seqLte, SEQ_SPACE } from './seq'

/**
 * TCP 32 位序列号运算(RFC 1982 序列号算术)。
 *
 * 序列号在 2^32 处回绕,因此不能用普通大小比较:4294967295 的"下一个"是 0。
 * 判定方式是看有符号差值落在半空间的哪一侧——这也意味着相距超过 2^31 的两个序列号
 * 无法定序(RFC 1982 称之为未定义),实现必须对该边界有确定行为而不是随机结果。
 */
describe('32 位序列号算术', () => {
  it('普通区间内按数值比较', () => {
    expect(seqLt(100, 200)).toBe(true)
    expect(seqGt(200, 100)).toBe(true)
    expect(seqLt(200, 100)).toBe(false)
    expect(seqCmp(100, 200)).toBeLessThan(0)
    expect(seqCmp(200, 100)).toBeGreaterThan(0)
    expect(seqCmp(100, 100)).toBe(0)
  })

  it('相等时 lt/gt 为假,lte/gte 为真', () => {
    expect(seqLt(5, 5)).toBe(false)
    expect(seqGt(5, 5)).toBe(false)
    expect(seqLte(5, 5)).toBe(true)
    expect(seqGte(5, 5)).toBe(true)
  })

  it('跨 2^32 回绕:回绕后的小数值仍"大于"回绕前的大数值', () => {
    const before = 4294967200 // 2^32 - 96
    const after = 104 // 回绕后
    expect(seqGt(after, before)).toBe(true)
    expect(seqLt(before, after)).toBe(true)
  })

  it('seqAdd 在 2^32 处回绕', () => {
    expect(seqAdd(4294967200, 200)).toBe(104)
    expect(seqAdd(0, 1)).toBe(1)
    expect(seqAdd(4294967295, 1)).toBe(0)
    // 加 0 保持不变
    expect(seqAdd(12345, 0)).toBe(12345)
  })

  it('seqAdd 结果始终落在 [0, 2^32)', () => {
    for (const [a, b] of [
      [4294967295, 100],
      [0, 0],
      [2147483648, 2147483648],
    ]) {
      const r = seqAdd(a, b)
      expect(r).toBeGreaterThanOrEqual(0)
      expect(r).toBeLessThan(SEQ_SPACE)
      expect(Number.isInteger(r)).toBe(true)
    }
  })

  it('seqDiff 给出有符号距离,跨回绕仍正确', () => {
    expect(seqDiff(200, 100)).toBe(100)
    expect(seqDiff(100, 200)).toBe(-100)
    // 回绕:104 在 4294967200 之后 104+96=200 字节
    expect(seqDiff(104, 4294967200)).toBe(200)
    expect(seqDiff(4294967200, 104)).toBe(-200)
  })

  it('seqDiff 对相同序列号为 0', () => {
    expect(seqDiff(0, 0)).toBe(0)
    expect(seqDiff(4294967295, 4294967295)).toBe(0)
  })

  it('半空间边界(相距恰好 2^31)有确定行为且不抛异常', () => {
    // RFC 1982 下该距离无法定序;要求实现给出确定结果而非随机/异常,
    // 以免分析引擎在极端流上产生不可复现的输出
    const a = 0
    const b = 2147483648 // 2^31
    expect(() => seqCmp(a, b)).not.toThrow()
    const r1 = seqCmp(a, b)
    const r2 = seqCmp(a, b)
    expect(r1).toBe(r2) // 确定性
  })

  it('接近半空间但仍可定序的距离判定正确', () => {
    const a = 0
    const b = 2147483647 // 2^31 - 1,仍在可定序范围
    expect(seqLt(a, b)).toBe(true)
    expect(seqGt(b, a)).toBe(true)
  })

  it('对未规范化输入(超出 32 位/负数)先归一再比较', () => {
    // 解析层理论上只给出 [0,2^32) 的值,但畸形抓包可能越界;
    // 归一化避免把脏数据传播成错误的 Gap
    expect(seqAdd(-1, 1)).toBe(0)
    expect(seqCmp(4294967296, 0)).toBe(0) // 2^32 ≡ 0
  })
})
