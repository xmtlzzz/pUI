import { parsePackets } from './parsePackets'
import type { Packet } from '../model/types'

/**
 * 解析调度层(M5 性能项):把「在哪里解析」的决定集中在一处。
 *
 * - 文本 < 1MB:主线程直解析(Worker 往返与结构化克隆的开销大于收益,
 *   常见的小抓包/示例文件毫秒级完成,不值得起线程);
 * - ≥ 1MB:走 Worker(Vite 原生 new Worker,打包自动分 chunk),
 *   主线程在 JSON.parse + 字段投影期间保持可交互 —— 这是 10 万包场景的
 *   唯一卡顿源(实测 128MB 守卫内的 JSON 秒级)。
 *
 * Worker 池:单只常驻复用(解析是低频操作,一次打开一份抓包;
 * 单只足以让 UI 不冻结,多只反而增加内存与复杂度)。
 * Worker 创建失败(极端环境/CSP)自动回落主线程 —— 解析结果比线程形态重要。
 */

const WORKER_THRESHOLD = 1024 * 1024 // 1MB

let worker: Worker | null = null

interface Pending {
  resolve: (packets: Packet[]) => void
  reject: (err: Error) => void
}

let pending: Pending | null = null

function ensureWorker(): Worker | null {
  if (worker) return worker
  if (typeof Worker === 'undefined') return null
  try {
    worker = new Worker(new URL('./parseWorker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (ev: MessageEvent) => {
      const msg = ev.data as { kind: 'ok' | 'err'; packets?: Packet[]; error?: string }
      const p = pending
      pending = null
      if (!p) return
      if (msg.kind === 'ok' && msg.packets) p.resolve(msg.packets)
      else p.reject(new Error(msg.error ?? 'worker parse failed'))
    }
    worker.onerror = () => {
      const p = pending
      pending = null
      p?.reject(new Error('worker crashed'))
      // 崩溃的 Worker 不再复用;下次大文本直接主线程回落
      worker = null
    }
    return worker
  } catch {
    worker = null
    return null
  }
}

function parseInWorker(jsonText: string): Promise<Packet[]> {
  const w = ensureWorker()
  if (!w) return Promise.resolve(parsePackets(jsonText))
  if (pending != null) return Promise.reject(new Error('已有解析在进行中'))
  return new Promise<Packet[]>((resolve, reject) => {
    pending = { resolve, reject }
    w.postMessage({ kind: 'parse', jsonText })
  })
}

/**
 * 解析 tshark JSON 为 Packet[]:小文本主线程同步,大文本异步走 Worker。
 * 返回 Promise 统一调用方形态;同步路径立即 resolve,不引入额外延迟。
 */
export function parsePacketsAsync(jsonText: string): Promise<Packet[]> {
  if (jsonText.length < WORKER_THRESHOLD) {
    try {
      return Promise.resolve(parsePackets(jsonText))
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)))
    }
  }
  return parseInWorker(jsonText).catch(() => {
    // Worker 路径失败(创建失败/崩溃/消息异常):回落主线程重试一次。
    // 主线程也失败才把错误抛给调用方(与旧同步行为一致)
    worker = null
    pending = null
    return parsePackets(jsonText)
  })
}

/** 测试钩子:重置模块级 Worker 状态(单例池跨用例污染) */
export function resetParseWorkerForTest(): void {
  worker?.terminate()
  worker = null
  pending = null
}
