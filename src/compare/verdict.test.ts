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
  it('warns with exact observation-layer wording when loss event exists only on A', () => {
    const d = diff({
      events: [{ kind: 'possible-loss-or-delay', gapText: '100–200', recovered: false, onlyIn: 'A' }],
    })
    const warns = d.eventDiffs.length ? buildVerdicts(d) : []
    expect(warns).toEqual([
      {
        severity: 'warn',
        statement:
          'A 侧观察到缺口/重传,B 侧同流未见:缺失发生在 A→B 传输路径上的可能性较高(提示位置,不构成断言;B 侧抓包漏包亦可产生同样现象)',
      },
    ])
  })

  it('warns symmetrically when loss event exists only on B', () => {
    // 丢包类判定含缺口(possible-loss-or-delay 等);zero-window 无缺口不属丢包类
    const d = diff({
      events: [{ kind: 'possible-loss-or-delay', gapText: '300–400', recovered: true, onlyIn: 'B' }],
    })
    expect(buildVerdicts(d)).toEqual([
      {
        severity: 'warn',
        statement:
          'B 侧观察到缺口/重传,A 侧同流未见:缺失发生在 B→A 传输路径上的可能性较高(提示位置,不构成断言;A 侧抓包漏包亦可产生同样现象)',
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
