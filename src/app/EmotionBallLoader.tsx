import { useEffect, useRef } from 'react'

/**
 * emotion-ball 官方引擎的 React 封装(引擎由 index.html 全局加载,见
 * public/emotion-ball/,许可见该目录 NOTICE.md)。
 *
 * 在所有需要"加载中"反馈的场景复用:
 * - '36' 联网加载(启动屏)、'32' 处理中忙碌(抓包解析)、'40' 检索资料(hex 详情)
 * - emotionId 全集见 public/emotion-ball/js/emotions.js(00-41)
 *
 * 引擎缺席(测试环境/脚本加载失败)时退化为纯文字提示,不阻塞功能。
 */
export interface EmotionBallLoaderProps {
  /** 表情库 id(emotions.js);加载场景常用:36 联网加载 / 32 处理中忙碌 / 40 检索资料 */
  emotionId?: string
  /** 底部提示文案;变化时经 handleAIMessage 同步给引擎(不直接改 DOM) */
  tips?: string
  /** 球体容器尺寸(px) */
  size?: number
  className?: string
}

interface EngineInstance {
  destroy?: () => void
  handleAIMessage?: (msg: { emotionId?: string; tips?: string }) => void
}

interface EngineGlobal {
  create?: (el: HTMLElement, opts: { emotion: string; idle: boolean }) => EngineInstance
}

function engine(): EngineGlobal | null {
  return (window as unknown as { EmotionBall?: EngineGlobal }).EmotionBall ?? null
}

export function EmotionBallLoader({ emotionId = '36', tips, size = 120, className }: EmotionBallLoaderProps) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const instRef = useRef<EngineInstance | null>(null)

  // 创建/销毁:emotionId 变化走 handleAIMessage 热切换,不重建实例(引擎契约)
  useEffect(() => {
    const EB = engine()
    const host = hostRef.current
    if (!EB?.create || !host) return
    try {
      instRef.current = EB.create(host, { emotion: emotionId, idle: true })
    } catch {
      instRef.current = null
    }
    return () => {
      try {
        instRef.current?.destroy?.()
      } catch {
        /* 引擎销毁失败不阻塞卸载 */
      }
      instRef.current = null
    }
  }, [])

  // tips 变化同步给引擎(引擎 emit tips 事件,渲染归引擎,避免双写 DOM)
  useEffect(() => {
    instRef.current?.handleAIMessage?.({ emotionId, tips })
  }, [emotionId, tips])

  const hasEngine = engine()?.create != null
  return (
    <span className={`eb-loader${className ? ` ${className}` : ''}`} data-testid="emotion-ball-loader">
      {hasEngine ? (
        <span ref={hostRef} style={{ width: size, height: size, display: 'inline-block' }} />
      ) : (
        // 降级:引擎缺席时的最小占位(测试环境/极端加载失败)
        <span className="eb-loader-fallback" style={{ fontSize: Math.max(14, size / 4) }}>
          ●
        </span>
      )}
      {tips != null && <span className="eb-loader-tips">{tips}</span>}
    </span>
  )
}
