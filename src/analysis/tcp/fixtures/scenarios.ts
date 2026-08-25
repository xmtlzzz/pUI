/**
 * M0 分析场景抓包构造器(plan M0:「MVP 增加真实/合成 PCAP」)。
 *
 * 与 scripts/gen-fixtures.mjs 的区别:那里的 tcpseg() 固定 doff=5,不支持 TCP 选项,
 * 因而无法生成 SACK;此处的 tcpseg() 支持选项并据长度计算数据偏移,
 * 是 Gap/SACK/重传类场景的前提。
 *
 * 场景取自升级指南第 5 节的 canonical 链路,亦即 M4 三份对照案例的数据来源。
 */

const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff]
const u32 = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
const ip4 = (s: string): number[] => s.split('.').map(Number)
const mac = (s: string): number[] => s.split(':').map((h) => Number.parseInt(h, 16))

const eth = (dst: string, src: string, type: number, payload: number[]): number[] => [
  ...mac(dst),
  ...mac(src),
  ...u16(type),
  ...payload,
]

const ip4hdr = (src: string, dst: string, proto: number, payload: number[]): number[] => [
  0x45,
  0,
  ...u16(20 + payload.length),
  ...u16(0),
  ...u16(0),
  64,
  proto,
  ...u16(0),
  ...ip4(src),
  ...ip4(dst),
  ...payload,
]

/** TCP 段;options 会按 4 字节对齐补 NOP,并据总长设置数据偏移 */
function tcpseg(
  sport: number,
  dport: number,
  seq: number,
  ack: number,
  flags: number,
  options: number[] = [],
  payload: number[] = [],
): number[] {
  const opts = [...options]
  while (opts.length % 4) opts.push(1) // NOP 填充
  const doff = 5 + opts.length / 4
  if (doff > 15) throw new Error('TCP options exceed header space')
  return [
    ...u16(sport),
    ...u16(dport),
    ...u32(seq >>> 0),
    ...u32(ack >>> 0),
    (doff << 4) | ((flags >> 8) & 0x0f),
    flags & 0xff,
    ...u16(8192),
    ...u16(0),
    ...u16(0),
    ...opts,
    ...payload,
  ]
}

/** SACK permitted 选项(kind=4, len=2) */
const SACK_PERM = [4, 2]
/** SACK 选项(kind=5):块为 [左边界, 右边界) 的原始序列号 */
const sackOpt = (blocks: Array<[number, number]>): number[] => {
  const body = blocks.flatMap(([l, r]) => [...u32(l >>> 0), ...u32(r >>> 0)])
  return [5, 2 + body.length, ...body]
}

interface RawPacket {
  tsUs: number
  data: number[]
}

/** 最小 pcapng:SHB + IDB(ethernet) + 每包一个 EPB */
function pcapng(packets: RawPacket[]): Buffer {
  const blocks: Buffer[] = []
  const push = (type: number, body: number[]): void => {
    const padded = [...body]
    while (padded.length % 4) padded.push(0)
    const total = 12 + padded.length
    blocks.push(Buffer.from([...u32(type), ...u32(total), ...padded, ...u32(total)]))
  }
  // SHB:字节序魔数 + 版本 1.0 + section length 未知
  push(0x0a0d0d0a, [...u32(0x1a2b3c4d), ...u16(1), ...u16(0), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
  // IDB:linktype=1(ethernet), snaplen=65535
  push(0x00000001, [...u16(1), ...u16(0), ...u32(65535)])
  for (const p of packets) {
    const us = BigInt(p.tsUs)
    push(0x00000006, [
      ...u32(0),
      ...u32(Number(us >> 32n)),
      ...u32(Number(us & 0xffffffffn)),
      ...u32(p.data.length),
      ...u32(p.data.length),
      ...p.data,
    ])
  }
  return Buffer.concat(blocks)
}

const CLIENT = { ip: '192.168.1.10', mac: '00:11:22:33:44:55' }
const SERVER = { ip: '93.184.216.34', mac: '00:aa:bb:cc:dd:ee' }
const SPORT = 54321
const DPORT = 80
/** 每段载荷字节数,便于用 100 的倍数手算序列号 */
const MSS = 100

const FIN = 0x01
const SYN = 0x02
const PSH = 0x08
const ACK = 0x10

const us = (t: number): number => Math.round(t * 1_000_000)
const payload = (n: number): number[] => new Array(n).fill(0x41)

interface SegOpts {
  seq: number
  ack?: number
  flags: number
  t: number
  opts?: number[]
  len?: number
}

/** 客户端 → 服务端 */
const c2s = (o: SegOpts): RawPacket => ({
  tsUs: us(o.t),
  data: eth(
    SERVER.mac,
    CLIENT.mac,
    0x0800,
    ip4hdr(CLIENT.ip, SERVER.ip, 6, tcpseg(SPORT, DPORT, o.seq, o.ack ?? 0, o.flags, o.opts ?? [], payload(o.len ?? 0))),
  ),
})

/** 服务端 → 客户端 */
const s2c = (o: SegOpts): RawPacket => ({
  tsUs: us(o.t),
  data: eth(
    CLIENT.mac,
    SERVER.mac,
    0x0800,
    ip4hdr(SERVER.ip, CLIENT.ip, 6, tcpseg(DPORT, SPORT, o.seq, o.ack ?? 0, o.flags, o.opts ?? [], payload(o.len ?? 0))),
  ),
})

/** 三次握手(双方声明 SACK permitted),数据序列号自 1 起 */
const handshake = (t0 = 0): RawPacket[] => [
  c2s({ seq: 0, flags: SYN, opts: [...SACK_PERM], t: t0 }),
  s2c({ seq: 0, ack: 1, flags: SYN | ACK, opts: [...SACK_PERM], t: t0 + 0.01 }),
  c2s({ seq: 1, ack: 1, flags: ACK, t: t0 + 0.02 }),
]

export interface ScenarioCaptures {
  /** 正常连续传输:逐段 ACK,正常四次挥手关闭 */
  normal: Buffer
  /** Gap + Dup ACK×3 + SACK 增长 + 重传 + 恢复 ACK(指南 Event #27 形态) */
  gapSack: Buffer
  /** 乱序后补齐且无重传(tshark 会误标 retransmission) */
  outOfOrder: Buffer
  /** 伪重传:数据已被确认后重发,序列空间无 Gap */
  spurious: Buffer
  /** 中途抓包:无握手、高起始序列号、一个真实 Gap */
  midStream: Buffer
}

export function buildScenarioCaptures(): ScenarioCaptures {
  const normal = pcapng([
    ...handshake(),
    ...[0, 1, 2, 3, 4].flatMap((i) => [
      c2s({ seq: 1 + i * MSS, ack: 1, flags: PSH | ACK, len: MSS, t: 0.03 + i * 0.02 }),
      s2c({ seq: 1, ack: 1 + (i + 1) * MSS, flags: ACK, t: 0.04 + i * 0.02 }),
    ]),
    c2s({ seq: 1 + 5 * MSS, ack: 1, flags: FIN | ACK, t: 0.2 }),
    s2c({ seq: 1, ack: 2 + 5 * MSS, flags: FIN | ACK, t: 0.21 }),
    c2s({ seq: 2 + 5 * MSS, ack: 2, flags: ACK, t: 0.22 }),
  ])

  // 缺 101..201:随后三段继续到达,接收端累计 ACK 停在 101 并用 SACK 报告已收到的块,
  // 发送端重传缺口,ACK 一次跃进到 501(恢复)
  const gapSack = pcapng([
    ...handshake(),
    c2s({ seq: 1, ack: 1, flags: PSH | ACK, len: MSS, t: 0.03 }),
    s2c({ seq: 1, ack: 101, flags: ACK, t: 0.04 }),
    c2s({ seq: 201, ack: 1, flags: PSH | ACK, len: MSS, t: 0.05 }),
    s2c({ seq: 1, ack: 101, flags: ACK, opts: sackOpt([[201, 301]]), t: 0.06 }),
    c2s({ seq: 301, ack: 1, flags: PSH | ACK, len: MSS, t: 0.07 }),
    s2c({ seq: 1, ack: 101, flags: ACK, opts: sackOpt([[201, 401]]), t: 0.08 }),
    c2s({ seq: 401, ack: 1, flags: PSH | ACK, len: MSS, t: 0.09 }),
    s2c({ seq: 1, ack: 101, flags: ACK, opts: sackOpt([[201, 501]]), t: 0.1 }),
    c2s({ seq: 101, ack: 1, flags: PSH | ACK, len: MSS, t: 0.25 }), // 重传缺口
    s2c({ seq: 1, ack: 501, flags: ACK, t: 0.26 }), // 恢复 ACK
  ])

  // A(1..101)、C(201..301)、B(101..201) 迟到补齐:全程无重发,ACK 直接推进到 301
  const outOfOrder = pcapng([
    ...handshake(),
    c2s({ seq: 1, ack: 1, flags: PSH | ACK, len: MSS, t: 0.03 }),
    s2c({ seq: 1, ack: 101, flags: ACK, t: 0.04 }),
    c2s({ seq: 201, ack: 1, flags: PSH | ACK, len: MSS, t: 0.05 }),
    c2s({ seq: 101, ack: 1, flags: PSH | ACK, len: MSS, t: 0.052 }),
    s2c({ seq: 1, ack: 301, flags: ACK, t: 0.06 }),
  ])

  // 101..201 已被 ACK 到 201,发送端仍重发同一段(通常因 ACK 未被发送端看到)
  const spurious = pcapng([
    ...handshake(),
    c2s({ seq: 1, ack: 1, flags: PSH | ACK, len: MSS, t: 0.03 }),
    s2c({ seq: 1, ack: 101, flags: ACK, t: 0.04 }),
    c2s({ seq: 101, ack: 1, flags: PSH | ACK, len: MSS, t: 0.05 }),
    s2c({ seq: 1, ack: 201, flags: ACK, t: 0.06 }),
    c2s({ seq: 101, ack: 1, flags: PSH | ACK, len: MSS, t: 0.3 }),
    s2c({ seq: 1, ack: 201, flags: ACK, t: 0.31 }),
  ])

  // 无握手,起始序列号 500001;真实缺口 500101..500201,SACK 用原始序号报告
  const midStream = pcapng([
    c2s({ seq: 500001, ack: 1, flags: PSH | ACK, len: MSS, t: 0 }),
    s2c({ seq: 1, ack: 500101, flags: ACK, t: 0.01 }),
    c2s({ seq: 500201, ack: 1, flags: PSH | ACK, len: MSS, t: 0.02 }),
    s2c({ seq: 1, ack: 500101, flags: ACK, opts: sackOpt([[500201, 500301]]), t: 0.03 }),
    c2s({ seq: 500101, ack: 1, flags: PSH | ACK, len: MSS, t: 0.2 }),
    s2c({ seq: 1, ack: 500301, flags: ACK, t: 0.21 }),
  ])

  return { normal, gapSack, outOfOrder, spurious, midStream }
}
