// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parsePackets } from '../parse/parsePackets'
import { buildPacketTree } from './packetTree'

describe('packetTree 覆盖全部内置示例帧(无崩溃回归)', () => {
  const fixtures = ['http', 'dns', 'mixed', 'lossy']
  it.each(fixtures)('%s 每一帧都能构建详情树', (name) => {
    const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/' + name + '.json'), 'utf-8')
    const packets = parsePackets(raw)
    expect(packets.length).toBeGreaterThan(0)
    for (const p of packets) {
      expect(() => {
        const tree = buildPacketTree(p)
        expect(tree.length).toBeGreaterThan(0)
      }).not.toThrow()
    }
  })
})