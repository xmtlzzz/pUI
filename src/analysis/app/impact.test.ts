import { describe, expect, it } from 'vitest'
import type { TcpEvent } from '../tcp/events'
import type { AppEvent } from './analyzers'
import { correlateImpacts, toImpactTcpRef } from './impact'

function tcpEv(o: Partial<TcpEvent> & { id: string; startTime: number; endTime: number }): TcpEvent {
  return {
    kind: 'possible-loss-or-delay',
    direction: 'c2s',
    severity: 'medium',
    recovered: false,
    evidenceScore: 5,
    duplicateAckCount: 0,
    duplicateAckPackets: [],
    sackPresent: false,
    observations: [],
    inference: { statement: '', confidence: 'medium', evidenceRefs: [] },
    limitations: [],
    ...o,
  } as TcpEvent
}

function appEv(o: Partial<AppEvent> & { id: string; time: number }): AppEvent {
  return {
    app: 'http',
    kind: 'response',
    packetNumber: 10,
    summary: 'HTTP 响应 200',
    ...o,
  }
}

describe('M6 ApplicationImpact — 时间窗重叠关联(措辞红线)', () => {
  it('窗口内关联:应用事件落在 TCP 事件 ±2s 内,陈述为"同期现象,可能相关,不构成因果"', () => {
    const impacts = correlateImpacts(
      [tcpEv({ id: '0:c2s:x:101', startTime: 10, endTime: 10.5 })],
      [appEv({ id: 'a', time: 11.8, summary: 'HTTP GET /api' })],
    )
    expect(impacts).toHaveLength(1)
    expect(impacts[0].tcp.kindLabel).toContain('疑似丢包')
    expect(impacts[0].statement).toBe(
      '「HTTP GET /api」与 疑似丢包 / 延迟到达 时间窗重叠(±2s):同期现象,可能相关,不构成因果',
    )
  })

  it('窗口外不关联(不强行拉郎配)', () => {
    const impacts = correlateImpacts(
      [tcpEv({ id: 'x', startTime: 10, endTime: 10.5 })],
      [appEv({ id: 'a', time: 20 })],
    )
    expect(impacts).toEqual([])
  })

  it('每个 TCP 事件只消费一次:重传风暴不把所有应用事件挂到同一条上', () => {
    const impacts = correlateImpacts(
      [tcpEv({ id: 'x', startTime: 0, endTime: 100 })],
      [
        appEv({ id: 'a', time: 10 }),
        appEv({ id: 'b', time: 50 }),
        appEv({ id: 'c', time: 90 }),
      ],
    )
    expect(impacts).toHaveLength(1) // 引擎序第一条重叠事件被消费后,其余不再关联
  })

  it('多 TCP 事件:按引擎序取首个未使用的重叠事件(未恢复/证据分优先)', () => {
    // 应用事件 t=11.5 同时落在 first(9±2 → 7-11.5,含边界)与 second(11-12±2)窗口;
    // 引擎序 first 在前且未使用 → 取 first(最显著优先)
    const impacts = correlateImpacts(
      [
        tcpEv({ id: 'first', kind: 'possible-loss-or-delay', startTime: 9, endTime: 9.5 }),
        tcpEv({ id: 'second', kind: 'reordering', startTime: 11, endTime: 12 }),
      ],
      [appEv({ id: 'a', time: 11.5 })],
    )
    expect(impacts).toHaveLength(1)
    expect(impacts[0].tcp.id).toBe('first')
  })

  it('toImpactTcpRef:kindLabel 与对照页同源(低置信乱序带疑似限定)', () => {
    const e = tcpEv({ id: 'r', kind: 'reordering', startTime: 0, endTime: 1 })
    ;(e as { inference: { confidence: string } }).inference.confidence = 'low'
    expect(toImpactTcpRef(e).kindLabel).toBe('疑似乱序(迟到补齐)')
  })
})
