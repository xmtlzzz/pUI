import type { AppEvent } from './analyzers'
import type { TcpEvent } from '../tcp/events'
import { kindLabelFor } from '../../m4/viewModel'
/**
 * M6 ApplicationImpact(plan §M6):应用层事件与 TCP 故障事件的**时间窗重叠**关联。
 *
 * 措辞红线(计划原文):只允许「相关/可能影响」级别的限定表述,绝不构成因果。
 * 单观察点下,应用层慢与 TCP 重传谁因谁果不可知(慢响应可能让窗口闲置,
 * 重传也可能让响应变慢),因此输出是"同期现象"陈述,不是归因结论。
 */

/** 关联判定所需的 TCP 事件最小投影(避免把整个 TcpEvent 泄漏进 UI 措辞) */
export interface ImpactTcpRef {
  id: string
  kindLabel: string
  startTime: number
  endTime: number
}

export interface AppImpact {
  /** 应用层事件 */
  app: AppEvent
  /** 时间窗重叠的 TCP 事件(证据分最高的一条;可能多条重叠,只报最显著一条) */
  tcp: ImpactTcpRef
  /** 限定措辞的关联陈述(直接可渲染) */
  statement: string
}

/** TCP 事件 -> 影响关联用引用(kindLabel 走与对照页同一来源,保证称谓一致) */
export function toImpactTcpRef(e: TcpEvent): ImpactTcpRef {
  return { id: e.id, kindLabel: kindLabelFor(e), startTime: e.startTime, endTime: e.endTime }
}

/**
 * 时间窗重叠关联:应用事件落在 TCP 事件 [start-W, end+W] 窗口内即视为重叠。
 * W 默认 2s:太窄漏掉相邻的 RTT 级延迟链,太宽把无关流量强行关联。
 * 每个 TCP 事件只消费一次(最显著 = 事件列表序,引擎已按未恢复/证据分排序),
 * 防止一个重传风暴把所有 HTTP 事件都挂到同一事件上刷屏。
 */
export function correlateImpacts(
  tcpEvents: ReadonlyArray<Parameters<typeof toImpactTcpRef>[0]>,
  appEvents: readonly AppEvent[],
  windowSec = 2,
): AppImpact[] {
  const refs = tcpEvents.map(toImpactTcpRef).map((r, i) => ({ ...r, order: i, used: false }))
  const out: AppImpact[] = []
  for (const app of appEvents) {
    let best: ((typeof refs)[number]) | null = null
    for (const r of refs) {
      if (r.used) continue
      if (app.time >= r.startTime - windowSec && app.time <= r.endTime + windowSec) {
        best = r // refs 按 engine 序,首个未使用的重叠事件即最显著
        break
      }
    }
    if (!best) continue
    best.used = true
    out.push({
      app,
      tcp: { id: best.id, kindLabel: best.kindLabel, startTime: best.startTime, endTime: best.endTime },
      statement: `「${app.summary}」与 ${best.kindLabel} 时间窗重叠(±${windowSec}s):同期现象,可能相关,不构成因果`,
    })
  }
  return out
}
