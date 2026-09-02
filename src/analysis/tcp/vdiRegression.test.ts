import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { analyzeStream } from './streamAnalysis.ts'
import { detectTcpEvents } from './events.ts'
import { computeSeqSpaceLayout } from '../../render/seqSpace.ts'
import { aggregateConversations } from '../../aggregate/aggregateConversations.ts'
import type { Packet } from '../../model/types'

/** VDI 真实抓包端到端:23844 包全链路必须亚秒完成(卡死回归护栏) */
describe('VDI 真实数据回归', () => {
  it('全链路 < 3s', () => {
    const lines = readFileSync('scripts/testdata/vdi_tcp.tsv', 'utf8').split('\n').filter(Boolean)
    const packets: Packet[] = []
    for (const line of lines) {
      const raw = line.replace(/\r$/, '')
      const [num, time, src, sport, dst, dport, seq, ack, len, retx, _dup, lost, sackLe, sackRe] = raw.split('%')
      const sackBlocks: Array<[number, number]> = []
      if (sackLe && sackRe) {
        const ls = sackLe.split(',')
        const rs = sackRe.split(',')
        for (let i = 0; i < ls.length; i++) if (ls[i] && rs[i]) sackBlocks.push([Number(ls[i]), Number(rs[i])])
      }
      const analysis: string[] = []
      if (retx) analysis.push('retransmission')
      if (lost) analysis.push('lost-segment')
      packets.push({
        number: Number(num), time: Number(time), len: 60, transport: 'TCP', proto: 'tcp',
        srcIp: src, srcPort: Number(sport), dstIp: dst, dstPort: Number(dport),
        tcpSeq: Number(seq), tcpAck: ack ? Number(ack) : undefined, tcpLen: Number(len) || 0,
        tcpFlags: '0x0018',
        tcpAnalysis: analysis.length ? analysis : undefined,
        tcpSackBlocks: sackBlocks.length ? sackBlocks : undefined,
      } as unknown as Packet)
    }
    const conv = aggregateConversations(packets, { slowResponseThreshold: 1 })[0]
    const t0 = performance.now()
    const facts = analyzeStream(conv.packets)
    const evs = detectTcpEvents(facts, conv.packets)
    const lay = computeSeqSpaceLayout(conv.packets, { client: conv.client, factsOverride: facts })
    const ms = performance.now() - t0
    console.log(`VDI_TOTAL=${Math.round(ms)}ms gaps=${facts.gaps.length} events=${evs.length} lanes=${lay.lanes.length}`)
    expect(ms).toBeLessThan(3000)
    expect(facts.gaps.length).toBeGreaterThan(0)
  })
})
