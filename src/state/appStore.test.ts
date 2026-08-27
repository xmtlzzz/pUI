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

  it('setTimeRange 自动定位窗口内报文最多的会话并高亮其窗口内报文', async () => {
    // 模拟真实:长会话横跨全部时间轴,单纯区间过滤列表不变;定位+高亮才是「能看到反应」的语义
    const a = [
      { ...pkt(101, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), time: 0.1 },
      { ...pkt(102, 'http', '2.2.2.2', 80, '1.1.1.1', 5000), time: 0.2 },
    ] as Packet[]
    const b = [
      { ...pkt(201, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), time: 5.1 },
      { ...pkt(202, 'dns', '8.8.8.8', 53, '1.1.1.1', 5000), time: 5.2 },
      { ...pkt(203, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), time: 5.3 },
    ] as Packet[]
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [...a, ...b], path: p }),
    )
    await useApp.getState().openFile('x.pcap')
    useApp.setState({ selectedId: null })
    // 窗口 [5,6):b 会话 3 报文命中,a 会话 0 → 应选中 b 会话并高亮其 3 个报文
    useApp.getState().setTimeRange({ start: 5, end: 6 })
    const st = useApp.getState()
    expect(st.selectedId).toBe(st.conversations.find((c) => c.protocol === 'dns')?.id)
    expect(st.highlight.length).toBe(3)
    expect(st.highlight).toEqual([201, 202, 203])
    // filtered 仍按区间重叠
    expect(st.filtered.map((c) => c.protocol)).toEqual(['dns'])
  })

  it('setTimeRange 高亮报文号超过 2000 时截断(仅保留前 2000),选中与计数仍用完整报文', async () => {
    const many = Array.from({ length: 2500 }, (_, i) => ({
      ...pkt(i + 1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80),
      time: i * 0.001,
    }) as Packet)
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets: many, path: p }))
    await useApp.getState().openFile('x.pcap')
    const big = useApp.getState().conversations[0]
    expect(big.packets.length).toBe(2500)
    // 窗口覆盖全部包:命中 2500 > 2000,高亮截断到前 2000,但选中仍指向该会话(bestCount 用原始计数)
    useApp.getState().setTimeRange({ start: 0, end: 3 })
    const st = useApp.getState()
    expect(st.selectedId).toBe(big.id)
    expect(st.highlight.length).toBeLessThanOrEqual(2000)
    expect(st.highlight).toEqual(many.slice(0, 2000).map((p) => p.number))
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

describe('M4 对照页导航状态', () => {
  const R = {
    conversationId: 'conv-1',
    eventIndex: 2,
    stageIndex: 3,
  }

  it('openCompare 重置事件下标;jumpFromCompare 记录来源且 closeCompare 不清除', () => {
    useApp.setState({ compareFor: 'old', compareEventIndex: 5, compareResume: null })
    useApp.getState().openCompare('conv-1')
    expect(useApp.getState().compareEventIndex).toBe(0)
    useApp.getState().setCompareEventIndex(4)
    expect(useApp.getState().compareEventIndex).toBe(4)
    // 负数钳制到 0
    useApp.getState().setCompareEventIndex(-3)
    expect(useApp.getState().compareEventIndex).toBe(0)

    useApp.getState().jumpFromCompare(R)
    useApp.getState().closeCompare()
    expect(useApp.getState().compareResume).toEqual(R) // 恢复入口仍可用
  })

  it('consumeCompareResume 读改一体:取走后为 null,再次取走返回 null', () => {
    useApp.setState({ compareResume: R })
    expect(useApp.getState().consumeCompareResume()).toEqual(R)
    expect(useApp.getState().compareResume).toBeNull()
    expect(useApp.getState().consumeCompareResume()).toBeNull()
  })

  it('clearCompareResume 兜底清除', () => {
    useApp.setState({ compareResume: R })
    useApp.getState().clearCompareResume()
    expect(useApp.getState().compareResume).toBeNull()
  })
})
