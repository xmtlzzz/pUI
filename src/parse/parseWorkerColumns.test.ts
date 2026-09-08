import { afterEach, describe, expect, it, vi } from 'vitest'
import { parsePacketsAsync, resetParseWorkerForTest } from './parseAsync'
import { handleParseMessage } from './parseWorker'
import { parsePackets } from './parsePackets'
import { packetColumns } from './packetCodec'
import type { Packet } from '../model/types'

function flatFrame(fields: Record<string, string>): string {
  return JSON.stringify({ _source: { layers: fields } })
}

function makeBigText(tag: string, frameNo: string): string {
  const f = flatFrame({ 'frame.number': frameNo, 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': tag })
  const frames: string[] = []
  const step = f.length + 33
  while (frames.length * step < 1024 * 1024 + 1024) frames.push(f)
  const text = `[${frames.join(',' + ' '.repeat(32))}]`
  if (text.length <= 1024 * 1024) throw new Error('makeBigText below worker threshold')
  return text
}

/** 可编程假 Worker(与 parseAsync.test.ts 同构;只驱动列式回传路径) */
class FakeWorker {
  static instances: FakeWorker[] = []
  onmessage: ((ev: { data: unknown }) => void) | null = null
  onerror: ((ev: unknown) => void) | null = null
  sent: Array<{ kind: string; jsonText?: string; requestId?: number }> = []
  responder: (req: { kind: string; jsonText?: string; requestId?: number }) => void = () => {}
  private scheduled = false

  constructor() {
    FakeWorker.instances.push(this)
  }
  postMessage(msg: { kind: string; jsonText?: string; requestId?: number }): void {
    this.sent.push(msg)
    if (this.scheduled) return
    this.scheduled = true
    setTimeout(() => {
      this.scheduled = false
      const batch = this.sent
      this.sent = []
      for (const m of batch) this.responder(m)
    }, 0)
  }
  terminate(): void {}
}

function stubWorkerClass(): void {
  FakeWorker.instances = []
  vi.stubGlobal('Worker', FakeWorker)
}

afterEach(() => {
  vi.unstubAllGlobals()
  resetParseWorkerForTest()
})

describe('parseWorker 列式回传协议(PacketLens 借鉴 #1:传输降维)', () => {
  it('handleParseMessage 回传 ok.columns(列式形态),不再携带逐包数组', () => {
    const text = makeBigText('10.8.0.1', '77')
    let resp: { kind: string; columns?: unknown; packets?: unknown; requestId?: number; error?: string } | undefined
    handleParseMessage({ kind: 'parse', jsonText: text, requestId: 5 }, (r) => {
      resp = r as NonNullable<typeof resp>
    })
    expect(resp?.kind).toBe('ok')
    expect(resp?.requestId).toBe(5)
    expect(resp?.packets).toBeUndefined()
    expect(resp?.columns).toBeDefined()
  }, 30_000)

  it('列式回传的通道对象数远小于逐包数组(传输降维的直接效果)', () => {
    const text = makeBigText('10.8.0.2', '78')
    const packets = parsePackets(text)
    const columns = packetColumns(packets)
    // 结构化克隆需遍历的对象:列式 = 容器 + 每列数组(几十);
    // 逐包 = 每包一个对象(本用例 >1MB 文本 ≈ 数千包,每包还有嵌套数组)
    const columnObjs = 1 + Object.keys(columns.columns).length
    const packetObjs = packets.length
    expect(packetObjs).toBeGreaterThan(1000)
    expect(columnObjs).toBeLessThan(packetObjs)
  }, 30_000)

  it('err 分支不受协议切换影响:仍回传 requestId + error', () => {
    let resp: { kind: string; error?: string; requestId?: number } | undefined
    handleParseMessage({ kind: 'parse', jsonText: '{broken', requestId: 9 }, (r) => {
      resp = r as NonNullable<typeof resp>
    })
    expect(resp?.kind).toBe('err')
    expect(resp?.requestId).toBe(9)
    expect(resp?.error).toBeTruthy()
  })
})

describe('parseAsync 接收列式回传(主线程重建 Packet[])', () => {
  it('Worker 回传 columns:parsePacketsAsync 解析结果与 parsePackets 逐字段一致', async () => {
    stubWorkerClass()
    const text = makeBigText('10.8.1.1', '81')
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          // 用真实 handleParseMessage 产生列式回应(非自证:走真实 Worker 代码)
          handleParseMessage({ kind: 'parse', jsonText: req.jsonText ?? '', requestId: req.requestId ?? -1 }, (resp) => {
            setTimeout(() => w.onmessage?.({ data: resp }), 0)
          })
        }
      }
    }
    const p = parsePacketsAsync(text)
    wire()
    const r: Packet[] = await p
    expect(r).toEqual(parsePackets(text))
  }, 30_000)

  it('通道序列化忠实性:columns 经 JSON 往返后重建,结果仍逐字段一致', async () => {
    stubWorkerClass()
    const text = makeBigText('10.8.1.2', '82')
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          handleParseMessage({ kind: 'parse', jsonText: req.jsonText ?? '', requestId: req.requestId ?? -1 }, (resp) => {
            // JSON 往返是比结构化克隆更苛刻的通道模拟(undefined 键被丢弃)
            const through = JSON.parse(JSON.stringify(resp))
            setTimeout(() => w.onmessage?.({ data: through }), 0)
          })
        }
      }
    }
    const p = parsePacketsAsync(text)
    wire()
    const r: Packet[] = await p
    expect(r).toEqual(parsePackets(text))
  }, 30_000)

  it('并发双请求经列式通道:各自结果正确、互不串扰', async () => {
    stubWorkerClass()
    const texts = [makeBigText('10.8.2.1', '91'), makeBigText('10.8.2.2', '92')]
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          handleParseMessage({ kind: 'parse', jsonText: req.jsonText ?? '', requestId: req.requestId ?? -1 }, (resp) => {
            setTimeout(() => w.onmessage?.({ data: resp }), 0)
          })
        }
      }
    }
    const p1 = parsePacketsAsync(texts[0])
    wire()
    const p2 = parsePacketsAsync(texts[1])
    wire()
    const [r1, r2] = await Promise.all([p1, p2])
    expect(new Set(r1.map((p) => p.srcIp))).toEqual(new Set(['10.8.2.1']))
    expect(new Set(r2.map((p) => p.srcIp))).toEqual(new Set(['10.8.2.2']))
    expect(r1[0].number).toBe(91)
    expect(r2[0].number).toBe(92)
  }, 30_000)
})
