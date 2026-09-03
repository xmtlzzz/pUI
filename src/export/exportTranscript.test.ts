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
  issues: [{ type: 'retransmission', message: '观察到 1 次 TCP 重传(重传本身不等于丢包,需结合序列空间缺口判断)' }],
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
    const rows = md.split(String.fromCharCode(10)).filter((l) => l.startsWith('| '))
    expect(rows).toHaveLength(4) // 表头 + 3 报文(分隔行以 |--- 开头,不计入)
    expect(md).toContain('| 1 | 0.000 | → 请求 | `tcp` | `TCP SYN` | 60B |')
    expect(md).toContain('⚠[`retransmission`]')
  })

  it('无异常时省略异常行', () => {
    const md = exportTranscript({ ...conv, issues: [] })
    expect(md).not.toContain('⚠ 异常')
  })

  it('不可信报文内容被 mdCell 转义:管道符/反引号/换行/尖括号不破坏表格结构', () => {
    const evil: Packet[] = [
      { number: 9, time: 1, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request',
        info: 'HTTP GET /a|b<img src=x onerror=alert(1)>`q`\nsecond line' },
    ]
    const md = exportTranscript({ ...conv, packets: evil, packetCount: 1 })
    const rows = md.split(String.fromCharCode(10)).filter((l) => l.startsWith('| '))
    expect(rows).toHaveLength(2) // 表头 + 1 报文:注入的换行/竖线未拆出多余表格行(分隔行 |--- 不以 "| " 开头)
    // 尖括号剥除、管道符转义、内部反引号转义、换行折叠为空格
    expect(md).toContain('\\|bimg src=x onerror=alert(1)\\`q\\` second line')
    expect(md).not.toContain('<img')
  })

  it('& 实体转义为 &amp;(防 Markdown 渲染器二次解码歧义)', () => {
    const evil: Packet[] = [
      { number: 9, time: 1, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request',
        info: 'GET /a&b<c>&d' },
    ]
    const md = exportTranscript({ ...conv, packets: evil, packetCount: 1 })
    // mdCell 包裹反引号,内部每个 & 实体转义(<c> 剥尖括号后留 c);原文的 & 不得裸透
    // (否则 &lt; &amp; 等字面量被渲染器二次解码产生歧义)
    expect(md).toContain('`GET /a&amp;bc&amp;d`')
    // 无裸 & 残留(允许的只有 &amp; 实体)
    expect(md.match(/&(?!amp;)/g) ?? []).toEqual([])
  })
})
describe('exportTranscript 紧凑模式(连续相同行合并为区间)', () => {
  const repeated: Packet[] = [
    { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
    { number: 2, time: 0.01, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
    { number: 3, time: 0.02, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' },
    // 方向变化:不合并
    { number: 4, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP ACK' },
    // 概要变化:不合并
    { number: 5, time: 0.04, len: 1400, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP PSH-ACK', tcpAnalysis: ['retransmission'] },
  ]
  const conv2: Conversation = { id: 'k2', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'tcp', packetCount: 5, bytes: 2000, start: 0, end: 0.04, duration: 0.04, packets: repeated, issues: [] }

  it('连续相同 3 行合并为 #1–#3 区间行,方向/概要变化处切新组', () => {
    const md = exportTranscript(conv2, true)
    // 压缩后应有表头 + 3 组(1-3 ACK / 4 ACK 反向 / 5 PSH)
    const rows = md.split(String.fromCharCode(10)).filter((l) => l.startsWith('| '))
    expect(rows).toHaveLength(4) // 表头 + 3 组
    expect(md).toContain('| #1–#3 | 3 | → 请求 | `tcp` | `TCP ACK` |')
    expect(md).toContain('| #4 | 1 | ← 响应 | `tcp` | `TCP ACK` |')
    expect(md).toContain('| #5 | 1 | → 请求 | `tcp` | `TCP PSH-ACK` ⚠[`retransmission`] |')
  })

  it('紧凑模式行数显著少于逐行模式(巨大会话防卡顿)', () => {
    const full = exportTranscript(conv2, null).split(String.fromCharCode(10))
    const compactMd = exportTranscript(conv2, true).split(String.fromCharCode(10))
    expect(compactMd.length).toBeLessThan(full.length)
  })

  it('单组内时间区间标注首末', () => {
    const md = exportTranscript(conv2, true)
    expect(md).toContain('#1–#3') // 区间
  })
})
