import { parsePackets, parsePacketsBatchPush } from './parsePackets'
import type { Packet } from '../model/types'

/**
 * 解析调度层(M5 性能项):把「在哪里解析」的决定集中在一处。
 *
 * - 文本 < 1MB:主线程直解析(Worker 往返与结构化克隆的开销大于收益,
 *   常见的小抓包/示例文件毫秒级完成,不值得起线程);
 * - ≥ 1MB:走 Worker 池(Vite 原生 new Worker,打包自动分 chunk),
 *   主线程在 JSON.parse + 字段投影期间保持可交互 —— 这是 10 万包场景的
 *   唯一卡顿源(实测 128MB 守卫内的 JSON 秒级)。
 *
 * Worker 池(M6 并发化):现网用户会快速连续打开两份抓包、或对比场景同时解析
 * 两份 —— 单只 Worker 的串行 pending 会让第二个请求排队甚至被拒。
 * 池大小 = min(4, os.availableParallelism()):
 * - availableParallelism 优先:某些 worker 沙箱里 os.cpus() 返回空数组
 *   (perfGuard.test.ts 有先例,uv_available_parallelism 不受此影响);
 * - 上限 4:解析是低频操作,更多并发只增内存与调度复杂度。
 * 调度:空闲 Worker 优先,无空闲则请求入队 FIFO。
 * 并发正确性:每只 Worker 项持有自己的 pending map,自增 requestId 关联
 * 消息与请求 —— 消息错序/穿插也不会串扰。
 * Worker 崩溃:reject 该 Worker 上所有 in-flight(由调用方的回落路径兜底主线程重解),
 * 池缩容并按需重建;队列中的请求改派其他 Worker。
 * Worker 创建失败(极端环境/CSP)自动回落主线程 —— 解析结果比线程形态重要。
 */

const WORKER_THRESHOLD = 1024 * 1024 // 1MB

/** 池上限:解析是低频操作,4 只足以覆盖「同时解析两份 + 余量」,再多只增内存 */
const MAX_POOL = 4

/** 池大小:min(4, os.availableParallelism())。vitest worker 沙箱里
 *  os.cpus() 可能返回空数组(perfGuard.test.ts 先例),故 availableParallelism
 *  优先;两者都不可用时保守按 1(行为退化为单 Worker,仍正确)。 */
export function poolSizeFor(osLike: Pick<typeof import('node:os'), 'availableParallelism' | 'cpus'> = os): number {
  try {
    const n = osLike.availableParallelism?.() ?? 0
    if (n > 0) return Math.min(MAX_POOL, n)
  } catch {
    /* fallthrough */
  }
  const cpus = osLike.cpus?.() ?? []
  return Math.min(MAX_POOL, Math.max(1, cpus.length || 1))
}

import os from 'node:os'

interface WorkerLike {
  onmessage: ((ev: { data: unknown }) => void) | null
  onerror: ((ev: unknown) => void) | null
  postMessage(msg: unknown): void
  terminate(): void
}

/** 请求消息(带 requestId:并发下消息与请求的关联键) */
interface ParseRequestMsg {
  kind: 'parse'
  jsonText: string
  requestId: number
}

interface Pending {
  resolve: (packets: Packet[]) => void
  reject: (err: Error) => void
}

/** 池中一只 Worker 及其状态 */
interface PoolEntry {
  worker: WorkerLike
  /** 该 Worker 上 in-flight 的请求:requestId → Pending。
   *  每只 Worker 独立持有 —— 并发正确性的关键(替换旧单一 pending 变量) */
  pending: Map<number, Pending>
  busy: boolean
}

interface QueuedRequest {
  jsonText: string
  start: (entry: PoolEntry) => void
}

let pool: PoolEntry[] = []
let queue: QueuedRequest[] = []
let nextRequestId = 1

/** 池调度纯函数(可注入单测):返回空闲项下标,无空闲返回 -1。
 *  策略「空闲优先」;多只空闲时取最早创建的(下标最小,稳定可测)。 */
export function pickIdle(entries: Array<{ busy: boolean }>): number {
  return entries.findIndex((e) => !e.busy)
}

function spawnEntry(): PoolEntry | null {
  try {
    const worker = new Worker(new URL('./parseWorker.ts', import.meta.url), { type: 'module' }) as unknown as WorkerLike
    const entry: PoolEntry = { worker, pending: new Map(), busy: false }
    worker.onmessage = (ev: { data: unknown }) => {
      const msg = ev.data as { kind: 'ok' | 'err'; packets?: Packet[]; error?: string; requestId?: number }
      const id = msg.requestId ?? -1
      const p = entry.pending.get(id)
      entry.pending.delete(id)
      entry.busy = entry.pending.size > 0
      if (!p) return // 未知 requestId(崩溃重建后的迟来消息):丢弃,不串扰
      if (msg.kind === 'ok' && msg.packets) p.resolve(msg.packets)
      else p.reject(new Error(msg.error ?? 'worker parse failed'))
      drainQueue()
    }
    worker.onerror = () => {
      // 崩溃:reject 该 Worker 上所有 in-flight(调用方回落主线程),
      // 池缩容(移除该项);队列请求会在下次调度时改派其他 Worker 或重建
      for (const [, p] of entry.pending) p.reject(new Error('worker crashed'))
      entry.pending.clear()
      entry.busy = false
      pool = pool.filter((e) => e !== entry)
      try {
        entry.worker.terminate()
      } catch {
        /* 已崩溃,terminate 失败可忽略 */
      }
      // 缩容后仍有队列:按需重建(空池则新建一只)继续消化
      drainQueue()
    }
    return entry
  } catch {
    return null
  }
}

/** 派发一个请求到 entry(占用其 busy 位,登记 pending map) */
function dispatch(entry: PoolEntry, jsonText: string, requestId: number, p: Pending): void {
  entry.busy = true
  entry.pending.set(requestId, p)
  entry.worker.postMessage({ kind: 'parse', jsonText, requestId } satisfies ParseRequestMsg)
}

/** 把队列中的请求尽量派给空闲 Worker(无空闲则留在队列,FIFO 保证不饿死) */
function drainQueue(): void {
  while (queue.length > 0) {
    const idleIdx = pickIdle(pool)
    if (idleIdx < 0) return // 无空闲:留在队列,等任一 onmessage/回调释放
    const entry = pool[idleIdx]
    const req = queue.shift()!
    req.start(entry)
  }
  // 队列已空且池为空(全部崩溃):不预建,下次请求按需重建
}

function parseInWorker(jsonText: string): Promise<Packet[]> {
  if (typeof Worker === 'undefined') return Promise.resolve(parsePackets(jsonText))
  return new Promise<Packet[]>((resolve, reject) => {
    const requestId = nextRequestId++
    const start = (entry: PoolEntry): void => {
      dispatch(entry, jsonText, requestId, { resolve, reject })
    }
    const idleIdx = pickIdle(pool)
    if (idleIdx >= 0) {
      // 空闲 Worker 优先:直接派发
      start(pool[idleIdx])
      return
    }
    if (pool.length < poolSizeFor()) {
      // 无空闲但池未满:扩容一只;创建失败回落主线程
      const entry = spawnEntry()
      if (entry) {
        pool.push(entry)
        start(entry)
        return
      }
      pool = []
      reject(new Error('worker create failed'))
      return
    }
    // 池满且无空闲:入队 FIFO(等任一 Worker 释放即派)
    queue.push({ jsonText, start })
  })
}

/**
 * 解析 tshark JSON 为 Packet[]:小文本主线程同步,大文本走 Worker 池(并发安全)。
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
    resetPool()
    return parsePackets(jsonText)
  })
}

/** 清空池状态(崩溃缩容/回落后的统一收尾;测试钩子复用) */
function resetPool(): void {
  for (const entry of pool) {
    try {
      entry.worker.terminate()
    } catch {
      /* 不可恢复的 Worker,忽略 terminate 失败 */
    }
  }
  pool = []
  queue = []
}

/** 测试钩子:重置模块级 Worker 池状态(跨用例污染) */
export function resetParseWorkerForTest(): void {
  resetPool()
  nextRequestId = 1
}

/**
 * 分批解析调度(M5 流式):Rust 按帧边界分批回传的批文本,逐批投影追加到 out。
 * 批解析固定在主线程逐批执行 —— 单批 ~4MB 文本的 parse 在毫秒级,
 * 且各批之间事件循环可呼吸(相比整段秒级 parse,不会长时间占住主线程);
 * Worker 化留待批数实测仍构成压力时再引入。
 */
export function parsePacketsBatch(state: { count: number }, batchText: string, out: Packet[]): void {
  parsePacketsBatchPush(state, batchText, out)
}
