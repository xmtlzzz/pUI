import { describe, expect, it } from 'vitest'
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
