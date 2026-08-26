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

describe('2^31 边界:比较器反对称性与排序稳定性', () => {
  const HALF = 0x8000_0000

  it('恰为 2^31 时两个方向符号相反(反对称)', () => {
    // 有符号差值在边界两向同为 -2^31,会让 seqCmp(a,b)/seqCmp(b,a) 同为负,
    // 成为非法比较器;修复后按归一化数值兜底,两方向必须反号
    const ab = seqCmp(0, HALF)
    const ba = seqCmp(HALF, 0)
    expect(Math.sign(ab)).toBe(-Math.sign(ba))
    expect(ab).not.toBe(0)
    expect(seqCmp(0, HALF)).toBe(ab) // 确定性:同输入同输出
  })

  it('伪随机样本上反对称处处成立', () => {
    // LCG 伪随机:固定序列、可复现,覆盖环上各个区域(含回绕附近)
    let x = 0x1234_5678
    const next = (): number => {
      x = (Math.imul(x, 1664525) + 1013904223) >>> 0
      return x
    }
    for (let i = 0; i < 2000; i++) {
      const a = next()
      const b = next()
      expect(Math.sign(seqCmp(a, b))).toBe(-Math.sign(seqCmp(b, a)))
    }
  })

  it('存在一致全序的集合:不同输入排列的排序结果一致', () => {
    // 集合整体落在不超过半空间的弧内(含恰为 2^31 的边界对,由数值兜底定序),
    // 此时 seqCmp 是合格的全序比较器,Array#sort 结果必须与输入顺序无关
    const expected = [0, 100, HALF - 100, HALF]
    const perms: number[][] = [
      [0, 100, HALF - 100, HALF],
      [HALF, HALF - 100, 100, 0],
      [HALF - 100, 0, HALF, 100],
      [100, HALF, 0, HALF - 100],
    ]
    for (const p of perms) {
      expect([...p].sort((a, b) => seqCmp(a, b))).toEqual(expected)
    }
  })

  it('三点张成整环时不存在全序,但两两判定确定且符合环近侧规则', () => {
    // RFC 1982 固有局限:A/B/C 两两相差均 <2^31,各自有确定的近侧先后;
    // 三点整体绕环一周则无一致全序(任何比较器都做不到),这里只钉住两两确定性
    const A = 0
    const B = 0x6000_0000
    const C = 0xc000_0000
    expect(seqCmp(B, A)).toBeGreaterThan(0)
    expect(seqCmp(C, B)).toBeGreaterThan(0)
    expect(seqCmp(A, C)).toBeGreaterThan(0) // A 经回绕后在 C 的近侧前方
    expect(seqCmp(C, A)).toBeLessThan(0)
  })
})
