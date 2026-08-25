import { describe, expect, it } from 'vitest'
import { tcpStatHint } from './tcpStatHints'
import type { TcpStatEntry } from './tcpStats'

const KEYS: Array<TcpStatEntry['key']> = [
  'retransmission',
  'fast-retransmission',
  'duplicate-ack',
  'lost-segment',
  'out-of-order',
]

/**
 * plan M1:标签解读文案不得把现象直接等价成结论。
 * 指南第 6 节明确 Retransmission ≠ 丢包、Out-of-Order ≠ 丢包、Lost Segment ≠ 真实网络丢包;
 * 这些文案是用户最先读到的解释,必须与分析层的证据化措辞一致。
 */
describe('tcpStatHint:不把现象写成因果结论', () => {
  it('各档位文案都不断言"就是丢包"', () => {
    for (const key of KEYS) {
      for (const [count, total] of [
        [1, 100],
        [5, 100],
        [30, 100], // heavy 档
      ] as Array<[number, number]>) {
        const hint = tcpStatHint(key, count, total)
        expect(hint, `${key} count=${count}`).not.toMatch(/典型原因是丢包|通常意味着丢包|丢包后超时重发|网络丢包较严重|对应网络丢包|说明丢包/)
      }
    }
  })

  it('重传文案提示需结合缺口判断,而非直接归因', () => {
    const hint = tcpStatHint('retransmission', 5, 100)
    expect(hint).toMatch(/重传/)
    // 保留"可能/需结合"这类限定语气
    expect(hint).toMatch(/可能|需结合|不等于/)
  })

  it('乱序文案明确乱序不等于丢包', () => {
    const hint = tcpStatHint('out-of-order', 5, 100)
    expect(hint).toMatch(/乱序/)
    expect(hint).not.toMatch(/丢包/)
  })

  it('丢段文案限定为"当前捕获视角",不声称网络丢包', () => {
    const hint = tcpStatHint('lost-segment', 3, 100)
    expect(hint).toMatch(/捕获|观察/)
    // 允许出现"网络丢包"字样,但必须是否定语境;把否定短语剥掉后不应再残留该断言
    expect(hint).toMatch(/不等于网络丢包/)
    expect(hint.replace(/不等于网络丢包/g, '')).not.toMatch(/网络丢包/)
  })

  it('保留数量与占比信息(不因改措辞丢掉事实)', () => {
    expect(tcpStatHint('retransmission', 1, 100)).toMatch(/1/)
    expect(tcpStatHint('retransmission', 30, 100)).toMatch(/30|30\.0%/)
    // heavy 档仍应给出占比
    expect(tcpStatHint('duplicate-ack', 30, 100)).toMatch(/%/)
  })

  it('数量为 1 时仍弱化措辞', () => {
    for (const key of KEYS) {
      expect(tcpStatHint(key, 1, 100)).toMatch(/1/)
    }
  })
})
