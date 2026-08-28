// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import { EmotionBallLoader } from './EmotionBallLoader'

afterEach(cleanup)

/** 引擎全局桩:记录 create/handleAIMessage/destroy 调用 */
function stubEngine() {
  const created: Array<{ el: HTMLElement; opts: { emotion: string; idle: boolean } }> = []
  const destroyed = vi.fn()
  const messages: Array<{ emotionId?: string; tips?: string }> = []
  ;(window as unknown as { EmotionBall: unknown }).EmotionBall = {
    create: (el: HTMLElement, opts: { emotion: string; idle: boolean }) => {
      created.push({ el, opts })
      return {
        destroy: destroyed,
        handleAIMessage: (m: { emotionId?: string; tips?: string }) => messages.push(m),
      }
    },
  }
  return { created, destroyed, messages }
}
function clearEngine() {
  delete (window as unknown as { EmotionBall?: unknown }).EmotionBall
}

describe('EmotionBallLoader — 官方引擎 React 封装', () => {
  afterEach(clearEngine)

  it('引擎在位:create 挂载到宿主容器,emotionId 透传', () => {
    const { created } = stubEngine()
    const { container } = render(<EmotionBallLoader emotionId="32" tips="解析中" size={80} />)
    expect(created).toHaveLength(1)
    expect(created[0].opts.emotion).toBe('32')
    expect(created[0].opts.idle).toBe(true)
    expect(container.querySelector('.eb-loader-tips')?.textContent).toBe('解析中')
    expect(container.querySelector('[data-testid="emotion-ball-loader"]')).toBeTruthy()
    void container
  })

  it('tips 变化经 handleAIMessage 热同步(不重建实例)', () => {
    const { created, messages } = stubEngine()
    const view = render(<EmotionBallLoader emotionId="32" tips="帧 0" />)
    view.rerender(<EmotionBallLoader emotionId="32" tips="帧 1234" />)
    expect(created).toHaveLength(1) // 不重建
    expect(messages.some((m) => m.tips === '帧 1234')).toBe(true)
  })

  it('emotionId 变化同样热切换', () => {
    const { created, messages } = stubEngine()
    const view = render(<EmotionBallLoader emotionId="32" />)
    view.rerender(<EmotionBallLoader emotionId="40" />)
    expect(created).toHaveLength(1)
    expect(messages.some((m) => m.emotionId === '40')).toBe(true)
  })

  it('卸载调用引擎 destroy(停 RAF)', () => {
    const { destroyed } = stubEngine()
    const view = render(<EmotionBallLoader emotionId="36" />)
    view.unmount()
    expect(destroyed).toHaveBeenCalledTimes(1)
  })

  it('引擎缺席(测试环境):降级为占位+文字,不抛错', () => {
    clearEngine()
    const { container } = render(<EmotionBallLoader emotionId="36" tips="正在启动" />)
    expect(container.querySelector('.eb-loader-fallback')).toBeTruthy()
    expect(container.querySelector('.eb-loader-tips')?.textContent).toBe('正在启动')
  })
})
