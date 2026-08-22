// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from 'vitest'

vi.mock('../bridge/tauri', () => ({
  openCapture: vi.fn(),
  openSample: vi.fn(),
  fetchHex: vi.fn(),
}))

import { openCapture, fetchHex } from '../bridge/tauri'
import { useApp } from './appStore'
import type { Packet } from '../model/types'

function pkt(n: number, proto: string, srcIp: string, srcPort: number, dstIp: string, dstPort: number): Packet {
  return { number: n, time: n, len: 60, transport: 'tcp', proto, srcIp, dstIp, srcPort, dstPort, direction: 'other' }
}

function meta(fileName: string) {
  return { fileName, packetCount: 1, interfaces: 1, timeStart: 0, timeEnd: 0, fileSize: 10 }
}

describe('appStore 加载一致性', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
    })
  })

  it('打开新文件时清空 hexCache,避免跨文件显示旧报文的 hex', async () => {
    const packets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    useApp.setState({ hexCache: { 5: 'AA' }, currentPath: 'a.pcap' })

    await useApp.getState().openFile('b.pcap')

    expect(useApp.getState().currentPath).toBe('b.pcap')
    expect(useApp.getState().hexCache).toEqual({})
    expect(useApp.getState().packets).toHaveLength(1)
  })

  it('openFile 记录解析耗时 parseMs', async () => {
    const packets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    await useApp.getState().openFile('b.pcap')
    const m = useApp.getState().meta
    expect(m).not.toBeNull()
    expect(typeof m?.parseMs).toBe('number')
    expect((m?.parseMs ?? -1) >= 0).toBe(true)
  })

  it('慢加载不覆盖已完成的较新加载', async () => {
    const slowPackets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    const fastPackets = [pkt(1, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53)]
    let resolveSlow!: (v: { meta: ReturnType<typeof meta>; packets: Packet[]; path: string }) => void
    vi.mocked(openCapture).mockImplementation((p: string) =>
      p === 'slow'
        ? new Promise((r) => {
            resolveSlow = r
          })
        : Promise.resolve({ meta: meta('fast.pcap'), packets: fastPackets, path: 'fast.pcap' }),
    )

    const slowLoad = useApp.getState().openFile('slow') // 先发起慢加载
    await useApp.getState().openFile('fast') // 后发起快加载,先完成
    expect(useApp.getState().conversations[0]?.protocol).toBe('dns')

    resolveSlow({ meta: meta('slow.pcap'), packets: slowPackets, path: 'slow.pcap' })
    await slowLoad
    expect(useApp.getState().conversations[0]?.protocol).toBe('dns') // 未被慢加载覆盖
    expect(useApp.getState().currentPath).toBe('fast.pcap')
  })

  it('fetchHexFor 并发请求同一帧只调用一次 fetchHex(去重)', async () => {
    vi.mocked(fetchHex).mockResolvedValue('AA')
    useApp.setState({ currentPath: 'x.pcap' })
    const [a, b] = await Promise.all([useApp.getState().fetchHexFor(1), useApp.getState().fetchHexFor(1)])
    expect(a).toBe('AA')
    expect(b).toBe('AA')
    expect(fetchHex).toHaveBeenCalledTimes(1)
  })

  it('setTimeRange 只保留与时间窗重叠的会话(区间下钻)', async () => {
    const early = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), { ...pkt(2, 'http', '2.2.2.2', 80, '1.1.1.1', 5000) } as Packet]
    const late = [pkt(3, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), { ...pkt(4, 'dns', '8.8.8.8', 53, '1.1.1.1', 5000) } as Packet]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets: [...early, ...late], path: p }))
    await useApp.getState().openFile('x.pcap')
    expect(useApp.getState().filtered).toHaveLength(2)
    useApp.getState().setTimeRange({ start: 2.5, end: 10 })
    expect(useApp.getState().filtered).toHaveLength(1)
    expect(useApp.getState().filtered[0].protocol).toBe('dns')
    useApp.getState().setTimeRange(null)
    expect(useApp.getState().filtered).toHaveLength(2)
  })

  it('hexCache 超过上限按 LRU 逐出最旧条目', async () => {
    vi.mocked(fetchHex).mockImplementation((_p: string, n: number) => Promise.resolve(`hex${n}`))
    useApp.setState({ currentPath: 'x.pcap' })
    const N = 205 // HEX_CACHE_LIMIT=200,超出 5 条触发逐出
    for (let i = 1; i <= N; i++) {
      await useApp.getState().fetchHexFor(i)
    }
    const cache = useApp.getState().hexCache
    expect(Object.keys(cache).length).toBeLessThanOrEqual(200)
    expect(cache[1]).toBeUndefined() // 最早的被逐出
    expect(cache[N]).toBe(`hex${N}`) // 最新的保留
  })

  it('fetchHexFor 在切换文件后丢弃旧文件的 hex 结果', async () => {
    vi.mocked(fetchHex).mockResolvedValue('STALE')
    useApp.setState({ currentPath: 'old.pcap' })
    const p = useApp.getState().fetchHexFor(1) // 挂起中(未 resolve)
    useApp.setState({ currentPath: 'new.pcap' })
    await p
    expect(useApp.getState().hexCache[1]).toBeUndefined() // 旧结果未写入新文件缓存
  })
})
