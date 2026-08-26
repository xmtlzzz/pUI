import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import gsap from 'gsap'
import type { StageBandEntry } from './viewModel'

/**
 * 对照页播放控制:驱动「当前时刻」这一个数字,所有元素状态由 React 依据该时刻声明式渲染。
 *
 * 设计约束(案例审批记录 + 计划 M4):
 * - GSAP 只负责补间 currentTime,绝不直接操作 DOM —— 布局零回流与 reduced-motion
 *   等价静态态因此天然成立;
 * - 可暂停(Space)、可单步(←/→)、可中断(Esc / stop());
 * - prefers-reduced-motion 下 refuseToPlay:phase 恒为 'static',组件渲染信息等价的静态终态;
 * - 单步以阶段为粒度(案例 openQuestion 已裁定 MVP 按分镜粒度恢复)。
 */

export type PlaybackPhase = 'idle' | 'playing' | 'paused' | 'done' | 'static'

export interface Playback {
  phase: PlaybackPhase
  /** 当前播放时刻(归一化 [0,1],与 StageBandEntry.t0/t1 同一坐标系) */
  time: number
  activeStageIndex: number
  play: () => void
  pause: () => void
  stepForward: () => void
  stepBack: () => void
  /** 中断并回到终态(Esc) */
  stop: () => void
}

const DURATION_MS = 3600 // 与 case-1 分镜总时长一致

/** 读一次系统 reduced-motion 偏好;SSR/无 window 时视为需要静态 */
function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : true
}

export function usePlayback(stages: StageBandEntry[], stageAt: (t: number) => number): Playback {
  const [phase, setPhase] = useState<PlaybackPhase>(() => (prefersReducedMotion() ? 'static' : 'idle'))
  const [time, setTime] = useState(0)
  const tweenRef = useRef<gsap.core.Tween | null>(null)

  const kill = useCallback(() => {
    tweenRef.current?.kill()
    tweenRef.current = null
  }, [])

  // 卸载时清理 tween,避免泄漏
  useEffect(() => kill, [kill])

  const play = useCallback(() => {
    if (prefersReducedMotion()) return // 静态模式拒绝播放
    kill()
    setPhase('playing')
    // 从当前 time 续播;已到终点则从头再来(重放)
    const from = time >= 0.999 ? 0 : time
    setTime(from)
    tweenRef.current = gsap.to(
      { t: from },
      {
        t: 1,
        duration: DURATION_MS * (1 - from),
        ease: 'none',
        paused: false,
        onComplete: () => setPhase('done'),
        onUpdate() {
          // this.targets()[0] 是补间对象本身
          const cur = (this.targets()[0] as { t: number }).t
          setTime(cur)
        },
      },
    )
  }, [kill, time])

  const pause = useCallback(() => {
    if (tweenRef.current) {
      tweenRef.current.pause()
      setPhase('paused')
    }
  }, [])

  const jumpToStageBoundary = useCallback(
    (idx: number, end: boolean) => {
      kill()
      const s = stages[idx]
      if (!s) return
      setTime(end ? s.t1 : s.t0)
      setPhase('paused')
    },
    [kill, stages],
  )

  const stepForward = useCallback(() => {
    const cur = stageAt(time)
    // 当前在阶段 i 内:前进到该阶段结束;已在边界:进入下一阶段起点
    const s = stages[cur]
    if (!s) {
      jumpToStageBoundary(0, false)
      return
    }
    const inStageTail = Math.abs(time - s.t1) < 1e-6
    if (inStageTail || time > s.t1) {
      jumpToStageBoundary(Math.min(cur + 1, stages.length - 1), stages.length === 1)
    } else {
      jumpToStageBoundary(cur, true)
    }
  }, [jumpToStageBoundary, stageAt, stages, time])

  const stepBack = useCallback(() => {
    const cur = stageAt(time)
    const s = stages[cur]
    if (!s) return
    const atStageHead = Math.abs(time - s.t0) < 1e-6
    if (atStageHead && cur > 0) {
      jumpToStageBoundary(cur - 1, false)
    } else {
      jumpToStageBoundary(cur, false)
    }
  }, [jumpToStageBoundary, stageAt, stages, time])

  const stop = useCallback(() => {
    kill()
    // 中断 = 直接呈现终态(信息等价的静态视图)
    setTime(1)
    setPhase(prefersReducedMotion() ? 'static' : 'done')
  }, [kill])

  const activeStageIndex = useMemo(() => stageAt(time), [stageAt, time])

  return { phase, time, activeStageIndex, play, pause, stepForward, stepBack, stop }
}
