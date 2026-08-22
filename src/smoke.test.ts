import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parsePackets } from './parse/parsePackets'
import { aggregateConversations } from './aggregate/aggregateConversations'

describe('smoke:真实抓包管线', () => {
  it('parse → aggregate 从内置 lossy 示例产出会话与异常', () => {
    const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/lossy.json'), 'utf-8')
    const packets = parsePackets(raw)
    expect(packets.length).toBeGreaterThan(0)
    const convs = aggregateConversations(packets)
    expect(convs.length).toBeGreaterThan(0)
    expect(convs.some((c) => c.issues.length > 0)).toBe(true) // lossy 示例必含异常场景
  })
})