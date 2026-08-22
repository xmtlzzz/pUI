import { describe, expect, it } from 'vitest'
import { exportTranscript } from './exportTranscript'
import type { Conversation, Packet } from '../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP SYN-ACK' },
  { number: 3, time: 0.5, len: 300, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'HTTP GET /', tcpAnalysis: ['retransmission'] },
]

const conv: Conversation = {
  id: 'k', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'http', packetCount: 3, bytes: 420,
  start: 0, end: 0.5, duration: 0.5, packets,
  issues: [{ type: 'retransmission', message: '检测到 1 次 TCP 重传,可能存在丢包' }],
}

describe('exportTranscript', () => {
  it('包含会话头部信息与异常摘要', () => {
    const md = exportTranscript(conv)
    expect(md).toContain('# 会话时序叙述')
    expect(md).toContain('客户端:')
    expect(md).toContain('1.1.1.1') // displayHost 已剥端口
    expect(md).toContain('服务端:')
    expect(md).toContain('2.2.2.2')
    expect(md).toContain('http · 3 包 · 420B')
    expect(md).toContain('⚠ 异常')
  })

  it('逐报文一行表格,含分析标注', () => {
    const md = exportTranscript(conv)
    const rows = md.split('\n').filter((l) => l.startsWith('| '))
    expect(rows).toHaveLength(4) // 表头 + 3 报文(分隔行以 |--- 开头,不计入)
    expect(md).toContain('| 1 | 0.000 | → 请求 | tcp | TCP SYN | 60B |')
    expect(md).toContain('⚠[retransmission]')
  })

  it('无异常时省略异常行', () => {
    const md = exportTranscript({ ...conv, issues: [] })
    expect(md).not.toContain('⚠ 异常')
  })
})