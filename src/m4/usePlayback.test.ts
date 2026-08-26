// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import type { StageBandEntry } from './viewModel'
import { usePlayback } from './usePlayback'

const stages: StageBandEntry[] = [
  { label: 'A', summary: 'a', fromPacket: 1, toPacket: 2, startTime: 0, endTime: 0.1, observationRefs: [], t0: 0, t1: 0.25 },
  { label: 'B', summary: 'b', fromPacket: 3, toPacket: 3, startTime: 0.2, endTime: 0.4, observationRefs: [], t0: 0.25, t1: 0.5 },
  { label: 'C', summary: 'c', fromPacket: 4, toPacket: 5, startTime: 0.6, endTime: 1, observationRefs: [], t0: 0.5, t1: 1 },
]

const stageAt = (t: number): number => {
  for (let i = stages.length - 1; i >= 0; i--) if (t >= stages[i].t0) return i
  return -1
}

describe('usePlayback', () => {
  it('初始为 idle(无 reduced-motion 时),时刻 0', () => {
    // jsdom 的 matchMedia 默认不含 reduce;若环境缺失则 hook 进入 static —— 两种都合法
    const { result } = renderHook(() => usePlayback(stages, stageAt))
    expect(['idle', 'static']).toContain(result.current.phase)
    expect(result.current.time).toBe(0)
    expect(result.current.activeStageIndex).toBe(0)
  })

  it('单步前进推进到阶段边界,单步后退回退', () => {
    const { result } = renderHook(() => usePlayback(stages, stageAt))
    act(() => result.current.stepForward()) // -> A 结束(t=0.25)
    expect(result.current.time).toBeCloseTo(0.25, 5)
    expect(result.current.activeStageIndex).toBe(1) // 已到 B 起点(按 t>=t0 判定)
    act(() => result.current.stepForward()) // -> B 结束(t=0.5)
    expect(result.current.time).toBeCloseTo(0.5, 5)
    act(() => result.current.stepBack()) // -> B 开始(t=0.25)
    expect(result.current.time).toBeCloseTo(0.25, 5)
    act(() => result.current.stepBack()) // -> A 开始(t=0)
    expect(result.current.time).toBeCloseTo(0, 5)
  })

  it('中断(stop)直接呈现终态(time=1)', () => {
    const { result } = renderHook(() => usePlayback(stages, stageAt))
    act(() => result.current.stop())
    expect(result.current.time).toBe(1)
    expect(['done', 'static']).toContain(result.current.phase)
    expect(result.current.activeStageIndex).toBe(2)
  })

  it('空阶段数组安全', () => {
    const { result } = renderHook(() => usePlayback([], () => -1))
    act(() => result.current.stepForward())
    act(() => result.current.stop())
    expect(result.current.time).toBeGreaterThanOrEqual(0)
  })
})
