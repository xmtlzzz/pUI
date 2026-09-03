import { afterEach, describe, expect, it, vi } from 'vitest'
import { parsePacketsAsync, resetParseWorkerForTest, cancelParse, ParseCancelledError, poolSizeFor } from './parseAsync'
import { parsePackets, parsePacketsBatchPush } from './parsePackets'
import { handleParseMessage } from './parseWorker'
import type { Packet } from '../model/types'

/**
 * 与 parsePackets.test.ts 同构的最小平铺帧构造
 */
function flatFrame(fields: Record<string, string>): string {
  return JSON.stringify({ _source: { layers: fields } })
}

const tcpFrame = (): string =>
  flatFrame({
    'frame.number': '1',
    'frame.time_relative': '0.0',
    'frame.len': '66',
    'frame.protocols': 'eth:ethertype:ip:tcp',
    'ip.src': '10.0.0.1',
    'ip.dst': '10.0.0.2',
    'tcp.srcport': '1234',
    'tcp.dstport': '80',
    'tcp.flags': '0x0018',
    'tcp.seq_raw': '1',
    'tcp.ack_raw': '1',
    'tcp.len': '0',
  })

/** 直接驱动真实 parseWorker.ts 的处理函数(handleParseMessage)并以 post 回调
 *  捕获回传 —— 验证 Worker 端回传协议本身(requestId 是否原样带回),
 *  不再是标了 requestId 的假 Worker 的自证循环。 */
function realWorkerReply(msg: { kind: string; jsonText?: string; requestId?: number }): {
  kind: string
  packets?: Packet[]
  error?: string
  requestId?: number
} | null {
  let out: { kind: string; packets?: Packet[]; error?: string; requestId?: number } | null = null
  handleParseMessage(msg, (resp) => {
    out = resp
  })
  return out
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('parsePacketsAsync — M5 Worker 化解析调度', () => {
  it('小文本(<1MB):主线程直解析,结果与 parsePackets 一致', async () => {
    const text = `[${tcpFrame()}]`
    const packets = await parsePacketsAsync(text)
    expect(packets).toHaveLength(1)
    expect(packets[0].number).toBe(1)
    expect(packets[0].srcIp).toBe('10.0.0.1')
    expect(packets[0].tcpFlags).toBe('0x0018')
    // 与同步入口完全等价
    expect(JSON.stringify(packets)).toBe(JSON.stringify(parsePackets(text)))
  })

  it('超大文本(≥1MB):Worker 不可用的测试环境下回落主线程,结果一致且不抛错', async () => {
    // jsdom/node 环境无真实 Worker(Vite worker URL 在 vitest 下不可实例化),
    // 调度层必须自动回落 —— 这是"解析结果比线程形态重要"红线的落地
    const frame = tcpFrame()
    // 拼到 1MB 以上(重复帧 + 恰当的 number/time 修正由 parsePackets 的回退兜底:
    // 缺 frame.number 时按序号补)
    const frames: string[] = []
    const filler = ' '.repeat(64)
    const step = frame.length + filler.length
    while (frames.length * step < 1024 * 1024 + 1) frames.push(frame)
    const text = `[${frames.join(',' + filler)}]`
    expect(text.length).toBeGreaterThan(1024 * 1024)

    const packets = await parsePacketsAsync(text)
    expect(packets.length).toBe(frames.length)
    // 与同步入口一致
    expect(packets.length).toBe(parsePackets(text).length)
  }, 30_000)

  it('解析错误(超大 JSON 守卫)经 Promise reject 透传,不静默吞掉', async () => {
    // MAX_PARSE_JSON = 128MB,构造 >128MB 的文本会 OOM,这里直接用
    // Worker 不可用回落后的同义路径:非法 JSON 必须以 Error 形态浮出
    await expect(parsePacketsAsync('{not-json')).rejects.toThrow()
  })

  it('确定性:同一输入两次解析结果逐字节一致', async () => {
    const text = `[${tcpFrame()},${tcpFrame().replace('"1"', '"2"')}]`
    const a = await parsePacketsAsync(text)
    const b = await parsePacketsAsync(text)
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
  })

  it('Worker 构造失败(Worker 为 undefined):回落主线程且不抛错', async () => {
    vi.stubGlobal('Worker', undefined)
    const frame = tcpFrame()
    const frames: string[] = []
    const filler = ' '.repeat(64)
    const step = frame.length + filler.length
    while (frames.length * step < 1024 * 1024 + 1) frames.push(frame)
    const text = `[${frames.join(',' + filler)}]`
    const packets = await parsePacketsAsync(text)
    expect(packets.length).toBe(frames.length)
    expect(packets[0].number).toBe(1)
  }, 30_000)

  it('阈值下(<1MB)直解:不触碰 Worker(全局被替换为 undefined 也成功)', async () => {
    vi.stubGlobal('Worker', undefined)
    const text = `[${tcpFrame()}]`
    const packets = await parsePacketsAsync(text)
    expect(packets).toHaveLength(1)
    expect(packets[0].number).toBe(1)
  })
})

describe('parsePacketsAsync — Worker 池(M6 并发解析)', () => {
  /** 可编程假 Worker:postMessage 只入队,宏任务边界后按当时的 responder 回放。
   *  语义对齐真实 Worker:主线程 postMessage 与测试接线(wire)之间没有顺序耦合 ——
   *  若 postMessage 同步调用 responder,接线晚于发请求的用例会静默丢消息(全超时)。 */
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
      if (this.scheduled) return // 已有排定回放:本次消息并入下一轮回放批次
      this.scheduled = true
      setTimeout(() => {
        this.scheduled = false
        const batch = this.sent
        this.sent = [] // 回放即消费:同一消息不重复回应(对齐真实 Worker 单次处理语义)
        for (const m of batch) this.responder(m)
      }, 0)
    }
    terminate(): void {}
    /** 模拟 Worker 正常回应 */
    replyOk(jsonText: string, requestId: number): void {
      const packets = parsePackets(jsonText)
      this.onmessage?.({ data: { kind: 'ok', packets, requestId } })
    }
    replyCrash(): void {
      this.onerror?.(new Error('boom'))
    }
  }

  function stubWorkerClass(): void {
    FakeWorker.instances = []
    vi.stubGlobal('Worker', FakeWorker)
  }

  function makeBigText(tag: string, frameNo: string): string {
    // ≥1MB 触发 Worker 路径;tag 唯一化各请求内容(互不串扰的断言依据)。
    // 构造后必须实测长度:step 估算(join 分隔符)偏小会落在阈值下,
    // 静默走主线程 → Worker 断言全部失真(崩溃用例曾因此红)
    const f = flatFrame({ 'frame.number': frameNo, 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': tag })
    const frames: string[] = []
    const step = f.length + 33 // 逗号 + 32 空格分隔符
    while (frames.length * step < 1024 * 1024 + 1024) frames.push(f)
    const text = `[${frames.join(',' + ' '.repeat(32))}]`
    if (text.length <= 1024 * 1024) throw new Error('makeBigText below worker threshold')
    return text
  }

  afterEach(() => resetParseWorkerForTest())

  it('并发 3 个请求:各自结果正确、互不串扰(红测试:requestId 关联)', async () => {
    stubWorkerClass()
    // 回应脚本:echo 回所收到的 jsonText 的解析结果 + 原样 requestId
    FakeWorker.instances.length = 0
    // 池默认大小 min(4, availableParallelism),构造时才实例化;responder 动态接
    const texts = [makeBigText('10.9.0.1', '11'), makeBigText('10.9.0.2', '22'), makeBigText('10.9.0.3', '33')]

    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          // 异步回应(模拟真实消息循环):Worker 算完再回
          setTimeout(() => w.replyOk(req.jsonText ?? '', req.requestId ?? -1), 0)
        }
      }
    }
    // Worker 是构造时创建的:先让 parsePacketsAsync 发请求,再接线
    const p1 = parsePacketsAsync(texts[0])
    wire()
    const p2 = parsePacketsAsync(texts[1])
    const p3 = parsePacketsAsync(texts[2])
    wire()

    const [r1, r2, r3] = await Promise.all([p1, p2, p3])
    // 互不串扰:每个结果只含自己 tag 的帧、帧号是自己的
    for (const [i, packets] of [r1, r2, r3].entries()) {
      expect(packets.length).toBeGreaterThan(0)
      const srcs = new Set(packets.map((p) => p.srcIp))
      expect(srcs.has(`10.9.0.${i + 1}`)).toBe(true)
      expect(srcs.size).toBe(1)
      expect(packets[0].number).toBe(Number([11, 22, 33][i]))
    }
  }, 30_000)

  it('请求超过池大小:入队 FIFO,全部最终完成且结果正确', async () => {
    stubWorkerClass()
    const texts = [0, 1, 2, 3, 4, 5].map((i) => makeBigText(`10.9.1.${i}`, String(100 + i)))
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          setTimeout(() => w.replyOk(req.jsonText ?? '', req.requestId ?? -1), 0)
        }
      }
    }
    const ps = texts.map((t) => {
      const p = parsePacketsAsync(t)
      wire()
      return p
    })
    const results = await Promise.all(ps)
    for (const [i, packets] of results.entries()) {
      const srcs = new Set(packets.map((p) => p.srcIp))
      expect(srcs.has(`10.9.1.${i}`)).toBe(true)
      expect(srcs.size).toBe(1)
    }
  }, 60_000)

  it('Worker 崩溃:in-flight 请求回落主线程,后续请求换新 Worker 可用', async () => {
    stubWorkerClass()
    const big = makeBigText('10.9.2.1', '7')
    // 回调返回 Promise:构造是同步的,但实例登记发生在 parsePacketsAsync()
    // 求值期间 —— await 一个已 reject/resolve 的 promise 前先让出微任务,
    // 保证断言执行时同步段(含 spawn)已完成。
    const p1 = parsePacketsAsync(big)
    await Promise.resolve()
    // 第 1 只 Worker 回应前先崩溃;池未满即扩容,此处实例必已存在
    const w1 = FakeWorker.instances[0]
    expect(w1).toBeDefined()
    w1.onerror?.(new Error('crash'))
    // 崩溃触发回落:resolve 值等于主线程解析
    const r1 = await p1
    expect(r1.length).toBe(parsePackets(big).length)
    // 后续请求:池按需重建新 Worker,可正常回应
    const p2 = parsePacketsAsync(big)
    const w2 = FakeWorker.instances[FakeWorker.instances.length - 1]
    expect(w2).not.toBe(w1)
    w2.responder = (req) => setTimeout(() => w2.replyOk(req.jsonText ?? '', req.requestId ?? -1), 0)
    const r2 = await p2
    expect(r2.length).toBe(r1.length)
  }, 30_000)

  it('真实 parseWorker 处理函数回传 requestId(回传协议非自证循环)', async () => {
    // 直接驱动 parseWorker.ts 的 onmessage 处理函数:验证 Worker 端回传响应
    // 确实带上了主线程派发时的 requestId —— 不再依赖假 Worker 手动 echo
    const text = makeBigText('10.9.0.1', '99')
    // 模拟主线程派发带 requestId 的请求(parseAsync 的真实派发形态)
    const out1 = realWorkerReply({ kind: 'parse', jsonText: text, requestId: 42 })
    expect(out1).toEqual({ kind: 'ok', packets: parsePackets(text), requestId: 42 })
    // err 分支同样回传 requestId
    const out2 = realWorkerReply({ kind: 'parse', jsonText: '{broken', requestId: 7 })
    expect(out2).toEqual({ kind: 'err', error: expect.any(String), requestId: 7 })
  }, 30_000)

  it('真实 Worker 回应路径下,并发双请求各自 resolve 且结果互不串扰', async () => {
    stubWorkerClass()
    const texts = [makeBigText('10.9.5.1', '51'), makeBigText('10.9.5.2', '52')]
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => {
          const out = realWorkerReply({ kind: 'parse', jsonText: req.jsonText ?? '', requestId: req.requestId ?? -1 })
          if (out) setTimeout(() => w.onmessage?.({ data: out }), 0)
        }
      }
    }
    const p1 = parsePacketsAsync(texts[0])
    wire()
    const p2 = parsePacketsAsync(texts[1])
    wire()
    const [r1, r2] = await Promise.all([p1, p2])
    expect(r1[0].srcIp).toBe('10.9.5.1')
    expect(r2[0].srcIp).toBe('10.9.5.2')
    expect(r1[0].number).toBe(51)
    expect(r2[0].number).toBe(52)
  }, 30_000)

  it('队列超出上限:立即 reject 超限请求(背压,不无限驻留内存)', async () => {
    stubWorkerClass()
    // 闷死所有 Worker:responder 不回 → in-flight 永不释放 → 队列越积越多
    // 池占满(poolSizeFor() 个 in-flight)+ 队列 2 个 = 6 个在途,第 7 个起超限即拒
    const inFlight = poolSizeFor()
    const texts = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => makeBigText(`10.9.7.${i}`, String(700 + i)))
    const overflowCount = texts.length - (inFlight + 2 /* MAX_QUEUE */)
    expect(overflowCount).toBeGreaterThan(0)
    const ps = texts.map((t) => parsePacketsAsync(t).catch((e) => e))
    // 只等超限的那几个(前 6 个停在 pending,await 会挂死)—— 断言它们全部被拒
    const settled = await Promise.all(ps.slice(-overflowCount))
    for (const r of settled) expect(r).toBeInstanceOf(Error)
    for (const r of settled) expect((r as Error).message).toContain('排队已满')
  }, 30_000)

  it('cancel 中途切换文件:cancel 之后未完成的请求 reject 为 ParseCancelledError', async () => {
    stubWorkerClass()
    // 闷死 Worker(不回应),让请求停在 in-flight;cancel 必须释放它们
    const big = makeBigText('10.9.8.1', '81')
    const p = parsePacketsAsync(big)
    await Promise.resolve()
    cancelParse()
    await expect(p).rejects.toBeInstanceOf(ParseCancelledError)
    // 取消后新请求仍可用(cancelParse 已清空池 → 按需重建新 Worker)
    const p2 = parsePacketsAsync(big)
    const w2 = FakeWorker.instances[FakeWorker.instances.length - 1]
    w2.responder = (req) => setTimeout(() => w2.replyOk(req.jsonText ?? '', req.requestId ?? -1), 0)
    const r2 = await p2
    expect(r2[0].srcIp).toBe('10.9.8.1')
  }, 30_000)

  it('cancel 也应拒绝排队中尚未派发的请求(不留内存驻留)', async () => {
    stubWorkerClass()
    // 恰好 = 在途(poolSizeFor) + 队列(MAX_QUEUE=2) 个请求:全部停在 in-flight/队列,
    // cancel 后都应 reject 为 ParseCancelledError(不得在队列里无限驻留文本)
    const inFlight = poolSizeFor()
    const texts = [0, 1, 2, 3, 4, 5].map((i) => makeBigText(`10.9.9.${i}`, String(900 + i)))
    const ps = texts.slice(0, inFlight + 2).map((t) => parsePacketsAsync(t).catch((e) => e))
    await Promise.resolve()
    cancelParse()
    const settled = await Promise.all(ps)
    expect(settled.length).toBe(ps.length)
    for (const r of settled) {
      expect(r).toBeInstanceOf(ParseCancelledError)
    }
  }, 30_000)

  it('解析中途取消后请求仍 resolve:对已完成的请求不受影响(仅在排队中/未返回时取消)', async () => {
    // 关闭闷死:回应正常。请求完成早于 cancel,取消不应影响已完成结果
    stubWorkerClass()
    const big = makeBigText('10.9.10.1', '101')
    const wire = (): void => {
      for (const w of FakeWorker.instances) {
        w.responder = (req) => setTimeout(() => w.replyOk(req.jsonText ?? '', req.requestId ?? -1), 0)
      }
    }
    const p = parsePacketsAsync(big)
    wire()
    const r = await p
    cancelParse() // 已完成之后取消:无挂起项,静默
    expect(r[0].srcIp).toBe('10.9.10.1')
  }, 30_000)
})

describe('parsePacketsBatch — M5 流式分批解析(Rust 帧边界批)', () => {
  /** Rust 批 = 帧对象裸序列(无外层 [ ],帧间逗号)。Rust 单测证明:
   *  批按帧边界切齐,闭括号后可能残留逗号 —— parsePacketsBatchPush 容错处理 */
  const batchOf = (...frames: string[]): string => frames.join(',') + ','

  it('分批解析结果与整段 parsePackets 逐字节一致(帧号回退跨批累计)', () => {
    const f1 = flatFrame({ 'frame.number': '1', 'frame.time_relative': '0', 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': '10.0.0.1', 'tcp.len': '0' })
    const f2 = flatFrame({ 'frame.number': '2', 'frame.time_relative': '0.1', 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': '10.0.0.2', 'tcp.len': '100' })
    const whole = parsePackets(`[${f1},${f2}]`)
    // 拆两批:批 1 = 帧 1;批 2 = 帧 2
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatchPush(state, batchOf(f1), out)
    parsePacketsBatchPush(state, batchOf(f2), out)
    expect(JSON.stringify(out)).toBe(JSON.stringify(whole))
  })

  it('单帧批与帧号缺失回退:回退帧号跨批累计(不重号)', () => {
    // 两批都无 frame.number 字段:回退序号必须全局递增
    const f = flatFrame({ 'frame.time_relative': '0', 'frame.protocols': 'eth:ethertype:ip:tcp', 'tcp.len': '0' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatchPush(state, batchOf(f), out)
    parsePacketsBatchPush(state, batchOf(f), out)
    expect(out.map((p) => p.number)).toEqual([1, 2])
  })

  it('一批多帧:单次 parse 覆盖整批,帧序保持', () => {
    const f1 = flatFrame({ 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const f2 = flatFrame({ 'frame.number': '2', 'frame.protocols': 'eth:ethertype:ip:udp' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatchPush(state, batchOf(f1, f2), out)
    expect(out.map((p) => p.number)).toEqual([1, 2])
    expect(out[0].transport).toBe('tcp')
    expect(out[1].transport).toBe('udp')
  })

  it('整段数组形态的批(防御):Rust 行为变化时仍可解析', () => {
    const f1 = flatFrame({ 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const f2 = flatFrame({ 'frame.number': '2', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatchPush(state, `[${f1},${f2}]`, out)
    expect(out).toHaveLength(2)
  })

  it('非法批文本必须抛错(不静默产出空包)', () => {
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    expect(() => parsePacketsBatchPush(state, '{broken', out)).toThrow()
  })

  it('Rust 真实批形态(大文件多批):首批带 [ 前缀/中批逗号开头/末批 ] 结尾——逐批解析与整段一致(用户 VDI 文件回归)', () => {
    // 这是从 run_capture_stream 切帧语义实测的批形态(曾因前端按想象的
    // "裸对象序列"假设解析,大文件全批失败 → 空会话无报错):
    //   首批 = '[\\n  {f1}'(数组开括号随第一帧进来)
    //   中批 = ',\\n  {fN}'(帧间逗号留在下帧切片头部)
    //   末批 = '\\n]'(EOF 冲尾,只剩数组闭括号)
    const mk = (n: string, ip: string, len: string): string =>
      flatFrame({
        'frame.number': n,
        'frame.time_relative': String(Number(n) * 0.1),
        'frame.len': '66',
        'frame.protocols': 'eth:ethertype:ip:tcp',
        'ip.src': ip,
        'tcp.len': len,
      })
    const whole = parsePackets(`[${mk('1', '10.0.0.1', '0')},${mk('2', '10.0.0.2', '100')},${mk('3', '10.0.0.1', '0')}]`)
    expect(whole).toHaveLength(3)

    const batches = [`[${mk('1', '10.0.0.1', '0')}`, `,${mk('2', '10.0.0.2', '100')}`, `,${mk('3', '10.0.0.1', '0')}`, '\n]']
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    let lastProgress = 0
    for (const b of batches) {
      parsePacketsBatchPush(state, b, out)
      lastProgress = state.count
    }
    expect(lastProgress).toBe(3)
    expect(JSON.stringify(out)).toBe(JSON.stringify(whole))
  })

  it('单批完整数组(小文件形态):整段 [..] 一批到达也能解析', () => {
    const mk = (n: string): string =>
      flatFrame({ 'frame.number': n, 'frame.time_relative': '0', 'frame.protocols': 'eth:ethertype:ip:tcp', 'tcp.len': '0' })
    const whole = parsePackets(`[${mk('1')},${mk('2')}]`)
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatchPush(state, `[${mk('1')},${mk('2')}]`, out)
    expect(JSON.stringify(out)).toBe(JSON.stringify(whole))
  })
})
