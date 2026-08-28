import { describe, expect, it, afterEach } from 'vitest'
import { parsePacketsAsync, parsePacketsBatch, resetParseWorkerForTest } from './parseAsync'
import { parsePackets } from './parsePackets'

/** 与 parsePackets.test.ts 同构的最小平铺帧构造 */
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

afterEach(() => resetParseWorkerForTest())

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
    parsePacketsBatch(state, batchOf(f1), out)
    parsePacketsBatch(state, batchOf(f2), out)
    expect(JSON.stringify(out)).toBe(JSON.stringify(whole))
  })

  it('单帧批与帧号缺失回退:回退帧号跨批累计(不重号)', () => {
    // 两批都无 frame.number 字段:回退序号必须全局递增
    const f = flatFrame({ 'frame.time_relative': '0', 'frame.protocols': 'eth:ethertype:ip:tcp', 'tcp.len': '0' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatch(state, batchOf(f), out)
    parsePacketsBatch(state, batchOf(f), out)
    expect(out.map((p) => p.number)).toEqual([1, 2])
  })

  it('一批多帧:单次 parse 覆盖整批,帧序保持', () => {
    const f1 = flatFrame({ 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const f2 = flatFrame({ 'frame.number': '2', 'frame.protocols': 'eth:ethertype:ip:udp' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatch(state, batchOf(f1, f2), out)
    expect(out.map((p) => p.number)).toEqual([1, 2])
    expect(out[0].transport).toBe('tcp')
    expect(out[1].transport).toBe('udp')
  })

  it('整段数组形态的批(防御):Rust 行为变化时仍可解析', () => {
    const f1 = flatFrame({ 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const f2 = flatFrame({ 'frame.number': '2', 'frame.protocols': 'eth:ethertype:ip:tcp' })
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    parsePacketsBatch(state, `[${f1},${f2}]`, out)
    expect(out).toHaveLength(2)
  })

  it('非法批文本必须抛错(不静默产出空包)', () => {
    const state = { count: 0 }
    const out: ReturnType<typeof parsePackets> = []
    expect(() => parsePacketsBatch(state, '{broken', out)).toThrow()
  })
})
