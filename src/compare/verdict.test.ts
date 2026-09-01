import { describe, expect, it } from 'vitest'
import { buildVerdicts } from './verdict'
import type { ConversationDiff, EventDiffEntry, PacketDiffStats } from './diff'

function diff(overrides?: { stats?: Partial<PacketDiffStats>; events?: EventDiffEntry[] }): ConversationDiff {
  return {
    stats: { countA: 10, countB: 10, bytesA: 1000, bytesB: 1000, ...overrides?.stats },
    eventDiffs: overrides?.events ?? [],
    timeline: [],
    truncated: false,
  }
}

describe('buildVerdicts', () => {
  it('warns with sender→observer path wording when loss event exists only on A (direction known)', () => {
    // 方向语义:c2s 数据的接收侧是服务端;A 侧观察到 c2s 缺口 = 客户端发出的数据
    // 在到达 A 观测点之前缺失 → 候选路径「客户端 发往 服务端 的数据在到达 A 之前」
    const d = diff({
      events: [{ kind: 'possible-loss-or-delay', gapText: '100–200', recovered: false, onlyIn: 'A', direction: 'c2s' }],
    })
    expect(buildVerdicts(d, { client: '10.0.0.8', server: '10.0.0.9' })).toEqual([
      {
        severity: 'warn',
        statement:
          'A 侧观察到缺口/重传,B 侧同流未见:10.0.0.8 发往10.0.0.9的数据在到达 A 侧 观测点之前缺失的可能性较高(提示位置,不构成断言;B 侧抓包漏包亦可产生同样现象)',
      },
    ])
  })

  it('falls back to direction-neutral wording when endpoints are not provided', () => {
    const d = diff({
      events: [{ kind: 'possible-loss-or-delay', gapText: '100–200', recovered: false, onlyIn: 'A' }],
    })
    expect(buildVerdicts(d)).toEqual([
      {
        severity: 'warn',
        statement:
          'A 侧观察到缺口/重传(方向未知数据),B 侧同流未见:缺失发生在该方向传输路径上的可能性较高(提示位置,不构成断言;B 侧抓包漏包亦可产生同样现象)',
      },
    ])
  })

  it('warns symmetrically when loss event exists only on B with s2c direction', () => {
    // s2c 数据的接收侧是客户端;B 侧观察到 s2c 缺口 = 服务端发往客户端的数据
    // 在到达 B 之前缺失(B 侧观测点贴近客户端/接收端)
    const d = diff({
      events: [{ kind: 'possible-loss-or-delay', gapText: '300–400', recovered: true, onlyIn: 'B', direction: 's2c' }],
    })
    expect(buildVerdicts(d, { client: '10.0.0.8', server: '10.0.0.9' })).toEqual([
      {
        severity: 'warn',
        statement:
          'B 侧观察到缺口/重传,A 侧同流未见:10.0.0.9 发往10.0.0.8的数据在到达 B 侧 观测点之前缺失的可能性较高(提示位置,不构成断言;A 侧抓包漏包亦可产生同样现象)',
      },
    ])
  })

  it('emits info when both sides observed the same event kind', () => {
    const d = diff({
      events: [{ kind: 'rst', gapText: undefined, recovered: true, onlyIn: 'both' }],
    })
    expect(buildVerdicts(d)).toEqual([
      { severity: 'info', statement: '两侧均观察到 rst:该现象横跨两点,非单点链路可解释' },
    ])
  })

  it('emits info on significant packet count divergence (>1.5x and >20 packets)', () => {
    const d = diff({ stats: { countA: 100, countB: 40 } }) // 2.5x,差 60 > 20
    expect(buildVerdicts(d)).toEqual([
      { severity: 'info', statement: '两侧报文计数差异显著(100 vs 40):可能与各侧采集位置/过滤差异有关' },
    ])
  })

  it('stays silent on insignificant packet count divergence', () => {
    // 比例 1.2x:低于 1.5x 阈值,不构成「显著」
    expect(buildVerdicts(diff({ stats: { countA: 60, countB: 50 } }))).toEqual([])
    // 比例够(1.75x)但差 15 ≤ 20:同样不构成
    expect(buildVerdicts(diff({ stats: { countA: 35, countB: 20 } }))).toEqual([])
  })

  it('triggers count divergence symmetrically when B side has more packets', () => {
    const d = diff({ stats: { countA: 40, countB: 100 } })
    expect(buildVerdicts(d)).toEqual([
      { severity: 'info', statement: '两侧报文计数差异显著(40 vs 100):可能与各侧采集位置/过滤差异有关' },
    ])
  })

  it('emits info "两侧观察一致" when there is no difference at all', () => {
    expect(buildVerdicts(diff())).toEqual([{ severity: 'info', statement: '两侧观察一致' }])
  })

  it('combines multiple verdict entries with warnings first', () => {
    const d = diff({
      stats: { countA: 100, countB: 40 },
      events: [
        { kind: 'possible-loss-or-delay', gapText: '1–2', recovered: false, onlyIn: 'A' },
        { kind: 'rst', gapText: undefined, recovered: true, onlyIn: 'both' },
      ],
    })
    const v = buildVerdicts(d)
    expect(v.map((x) => x.severity)).toEqual(['warn', 'info', 'info'])
  })
})
