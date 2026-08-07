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
})
