// @vitest-environment jsdom
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { computeMeta } from './tauri'

describe('bridge helpers', () => {
  it('computeMeta derives meta from packets', () => {
    const meta = computeMeta('demo.pcapng', [
      { number: 1, time: 0, len: 10, transport: 'tcp', proto: 'tcp', direction: 'other' },
      { number: 2, time: 5, len: 20, transport: 'tcp', proto: 'http', direction: 'request' },
    ] as never)
    expect(meta.packetCount).toBe(2)
    expect(meta.timeStart).toBe(0)
    expect(meta.timeEnd).toBe(5)
    expect(meta.fileName).toBe('demo.pcapng')
  })

  it('computeMeta handles empty packet list', () => {
    const meta = computeMeta('empty.pcapng', [] as never)
    expect(meta.packetCount).toBe(0)
    expect(meta.timeStart).toBe(0)
    expect(meta.timeEnd).toBe(0)
  })

  it('computeMeta 按 frame.interface_id 去重统计接口数,缺省回落 1', () => {
    const withIds = computeMeta('multi.pcapng', [
      { number: 1, time: 0, len: 10, transport: 'tcp', proto: 'tcp', direction: 'other', interfaceId: '0' },
      { number: 2, time: 1, len: 10, transport: 'tcp', proto: 'tcp', direction: 'other', interfaceId: '0' },
      { number: 3, time: 2, len: 10, transport: 'udp', proto: 'dns', direction: 'other', interfaceId: '1' },
    ] as never)
    expect(withIds.interfaces).toBe(2)
    const noIds = computeMeta('single.pcapng', [
      { number: 1, time: 0, len: 10, transport: 'tcp', proto: 'tcp', direction: 'other' },
    ] as never)
    expect(noIds.interfaces).toBe(1)
  })

  it('computeMeta 透传 parseMs', () => {
    const meta = computeMeta('demo.pcapng', [] as never, 0, 123.4)
    expect(meta.parseMs).toBe(123.4)
  })
})

// ---- 命令路由回归(mock @tauri-apps/api/core;需 jsdom 提供 window/btoa) ----
// 事故:receiveStreamedCapture 命令名写死,打开示例时 open_capture_data 的参数
// 被发往 open_capture,报「missing required key path」
import { vi } from 'vitest'

const invokeMock = vi.fn()
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
  Channel: class {
    onmessage: ((msg: unknown) => void) | null = null
  },
}))

describe('bridge 命令路由(流式打开,Tauri 分支)', () => {
  beforeEach(() => {
    invokeMock.mockReset()
    ;(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {}
  })
  afterEach(() => {
    delete (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__
  })

  it('openCapture → open_capture,携带 path 与 onChunk', async () => {
    const { openCapture } = await import('./tauri')
    invokeMock.mockResolvedValue({ size: 100, path: 'C:/x.pcap', frames: 0 })
    await openCapture('C:/x.pcap')
    expect(invokeMock).toHaveBeenCalledTimes(1)
    const [cmd, args] = invokeMock.mock.calls[0] as [string, Record<string, unknown>]
    expect(cmd).toBe('open_capture')
    expect(args.path).toBe('C:/x.pcap')
    expect(args.onChunk).toBeTruthy()
  })

  it('openSample → open_capture_data,携带 fileName/base64Data(事故回归)', async () => {
    const { openSample } = await import('./tauri')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        arrayBuffer: async () => new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a]).buffer,
      })),
    )
    invokeMock.mockResolvedValue({ size: 4, path: 'C:/tmp/demo.pcapng', frames: 0 })
    await openSample('demo')
    expect(invokeMock).toHaveBeenCalledTimes(1)
    const [cmd, args] = invokeMock.mock.calls[0] as [string, Record<string, unknown>]
    expect(cmd).toBe('open_capture_data')
    expect(args.fileName).toBe('demo.pcapng')
    expect(typeof args.base64Data).toBe('string')
    expect(args.onChunk).toBeTruthy()
    vi.unstubAllGlobals()
  })
})
