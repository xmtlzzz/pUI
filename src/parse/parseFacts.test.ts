import { describe, expect, it } from 'vitest'
import { parsePackets } from './parsePackets'

/** 构造平铺(-e)形态的单帧 JSON:平铺模式下每个字段值都是字符串数组 */
function flatFrame(fields: Record<string, string | string[]>): string {
  const layers: Record<string, string[]> = {}
  for (const [k, v] of Object.entries(fields)) layers[k] = Array.isArray(v) ? v : [v]
  return JSON.stringify([{ _source: { layers } }])
}

/** 构造协议树(-J)形态的单帧 JSON:字段嵌在协议子对象里 */
function treeFrame(tcp: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  return JSON.stringify([
    {
      _source: {
        layers: {
          frame: { 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp', 'frame.len': '100' },
          ip: { 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.2' },
          tcp: { 'tcp.srcport': '1234', 'tcp.dstport': '80', ...tcp },
          ...extra,
        },
      },
    },
  ])
}

const BASE = {
  'frame.number': '1',
  'frame.protocols': 'eth:ethertype:ip:tcp',
  'frame.len': '154',
  'ip.src': '10.0.0.1',
  'ip.dst': '10.0.0.2',
  'tcp.srcport': '1234',
  'tcp.dstport': '80',
}

describe('parsePackets — M0 新增事实字段', () => {
  it('解析 tcp.stream 为数值流 id', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.stream': '3' }))
    expect(p.tcpStream).toBe(3)
  })

  it('tcp.stream 缺失时为 undefined(不得伪造 0——0 是合法流 id)', () => {
    const [p] = parsePackets(flatFrame(BASE))
    expect(p.tcpStream).toBeUndefined()
  })

  it('解析 tcp.len 为载荷长度,且与 frame.len 区分', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'frame.len': '154', 'tcp.len': '100' }))
    expect(p.tcpLen).toBe(100)
    expect(p.len).toBe(154) // 帧长仍是帧长
  })

  it('零长度 ACK 的 tcp.len 为 0 而非 undefined(0 与"缺字段"语义不同)', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.len': '0' }))
    expect(p.tcpLen).toBe(0)
  })

  it('平铺模式下多块 SACK 按并行数组逐对 zip(实测 tshark 输出形态)', () => {
    const [p] = parsePackets(
      flatFrame({
        ...BASE,
        'tcp.options.sack_le': ['201', '401', '601'],
        'tcp.options.sack_re': ['301', '501', '701'],
      }),
    )
    // 只取首元素会丢掉第 2、3 块,进而漏掉两个 Gap
    expect(p.tcpSackBlocks).toEqual([
      [201, 301],
      [401, 501],
      [601, 701],
    ])
  })

  it('单块 SACK 也解析为长度 1 的块数组', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.options.sack_le': '201', 'tcp.options.sack_re': '301' }))
    expect(p.tcpSackBlocks).toEqual([[201, 301]])
  })

  it('无 SACK 时为 undefined 而非空数组(区分"没有 SACK"与"有 SACK 但空")', () => {
    const [p] = parsePackets(flatFrame(BASE))
    expect(p.tcpSackBlocks).toBeUndefined()
  })

  it('左右边界数量不匹配时只取成对的部分,不产生 NaN 边界', () => {
    // 截断/畸形输出:右边界少一个。宁可少报一块,也不能产出 NaN 污染序列空间运算
    const [p] = parsePackets(
      flatFrame({ ...BASE, 'tcp.options.sack_le': ['201', '401'], 'tcp.options.sack_re': ['301'] }),
    )
    expect(p.tcpSackBlocks).toEqual([[201, 301]])
  })

  it('SACK 边界值可达 32 位上界且保持精确整数', () => {
    const [p] = parsePackets(
      flatFrame({ ...BASE, 'tcp.options.sack_le': '4294967200', 'tcp.options.sack_re': '4294967295' }),
    )
    expect(p.tcpSackBlocks).toEqual([[4294967200, 4294967295]])
  })

  it('解析 tcp.analysis.duplicate_ack_num', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.analysis.duplicate_ack_num': '323' }))
    expect(p.tcpDupAckNum).toBe(323)
  })

  it('duplicate_ack 在平铺模式下产生两个数组条目时仍只算一个报文标签', () => {
    // 实测:单个 dup ACK 报文的 tcp.analysis.duplicate_ack 是 ["1","1"];
    // 按数组长度计数会把 dup ACK 数翻倍,标签必须去重
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.analysis.duplicate_ack': ['1', '1'] }))
    expect(p.tcpAnalysis?.filter((t) => t === 'duplicate-ack')).toHaveLength(1)
  })

  it('识别 spurious retransmission 标签', () => {
    const [p] = parsePackets(
      flatFrame({ ...BASE, 'tcp.analysis.retransmission': '1', 'tcp.analysis.spurious_retransmission': '1' }),
    )
    expect(p.tcpAnalysis).toContain('spurious-retransmission')
    expect(p.tcpAnalysis).toContain('retransmission')
  })

  it('解析 frame.cap_len,并可与 frame.len 比较判断截断', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'frame.len': '1514', 'frame.cap_len': '96' }))
    expect(p.capLen).toBe(96)
    expect(p.len).toBe(1514)
  })

  it('解析 tcp.completeness 位掩码', () => {
    const [full] = parsePackets(flatFrame({ ...BASE, 'tcp.completeness': '15' }))
    expect(full.tcpCompleteness).toBe(15)
    const [mid] = parsePackets(flatFrame({ ...BASE, 'tcp.completeness': '12' }))
    expect(mid.tcpCompleteness).toBe(12)
  })

  it('completeness 为 0 时保留 0(0 表示只见 SYN,不是"缺字段")', () => {
    const [p] = parsePackets(flatFrame({ ...BASE, 'tcp.completeness': '0' }))
    expect(p.tcpCompleteness).toBe(0)
  })

  it('协议树形态也能取到新增字段(旧 fixture 不破坏)', () => {
    const [p] = parsePackets(
      treeFrame({
        'tcp.stream': '2',
        'tcp.len': '100',
        'tcp.completeness': '15',
        'tcp.analysis': { 'tcp.analysis.duplicate_ack_num': '5' },
      }),
    )
    expect(p.tcpStream).toBe(2)
    expect(p.tcpLen).toBe(100)
    expect(p.tcpCompleteness).toBe(15)
    expect(p.tcpDupAckNum).toBe(5)
  })

  it('协议树形态的 SACK 嵌在 options_tree 里,能取到(但只剩最后一块)', () => {
    // 实测树形态会把多块 SACK 坍缩成只剩最后一块,且 count 仍报原始块数;
    // 解析层如实反映"只看到一块",由分析层据 count 不一致标注 SACK 视图不完整
    const [p] = parsePackets(
      treeFrame({
        'tcp.options_tree': {
          'tcp.options.sack_tree': {
            'tcp.options.sack_le': '601',
            'tcp.options.sack_re': '701',
            'tcp.options.sack.count': '3',
          },
        },
      }),
    )
    expect(p.tcpSackBlocks).toEqual([[601, 701]])
  })

  it('不因新增字段破坏既有字段解析', () => {
    const [p] = parsePackets(
      flatFrame({ ...BASE, 'tcp.flags': '0x0012', 'tcp.seq_raw': '4294967200', 'tcp.ack_raw': '101' }),
    )
    expect(p.tcpFlags).toBe('0x0012')
    expect(p.tcpSeq).toBe(4294967200)
    expect(p.tcpAck).toBe(101)
    expect(p.transport).toBe('tcp')
  })
})
