import { writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT = join(process.cwd(), 'public', 'fixtures')

// ---- 底层字节工具 ----
const u16 = (n) => [(n >> 8) & 0xff, n & 0xff]
const u32 = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
const ip4 = (s) => s.split('.').map(Number)
const mac = (s) => s.split(':').map((h) => parseInt(h, 16))
const eth = (dst, src, type, payload) => [...mac(dst), ...mac(src), ...u16(type), ...payload]
const ip4hdr = (src, dst, proto, payload) => {
  const len = 20 + payload.length
  return [0x45, 0, ...u16(len), ...u16(0), ...u16(0), 64, proto, ...u16(0), ...ip4(src), ...ip4(dst), ...payload]
}
const tcpseg = (sport, dport, seq, ack, flags, payload = []) => {
  const doff = 5
  const hdr = [...u16(sport), ...u16(dport), ...u32(seq >>> 0), ...u32(ack >>> 0), (doff << 4) | ((flags >> 8) & 0x0f), flags & 0xff, ...u16(8192), ...u16(0), ...u16(0)]
  return [...hdr, ...payload]
}
const udpseg = (sport, dport, payload = []) => [...u16(sport), ...u16(dport), ...u16(8 + payload.length), ...u16(0), ...payload]

// TCP flags
const FIN = 0x01
const SYN = 0x02
const PSH = 0x08
const ACK = 0x10

// ---- pcapng 写入 ----
function pcapng(packets) {
  // packets: [{ tsUs, data:number[] }]  tsUs 为绝对微秒时间戳
  const blocks = []
  const push = (type, body) => {
    const total = 12 + body.length + (body.length % 4 ? 4 - (body.length % 4) : 0)
    const padded = [...body]
    while (padded.length % 4) padded.push(0)
    blocks.push(Buffer.from([...u32(type), ...u32(total), ...padded, ...u32(total)]))
  }
  // SHB: 字节序魔数 + 版本(1,0) + section length(-1=未知)
  push(0x0a0d0d0a, [...u32(0x1a2b3c4d), ...u16(1), ...u16(0), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
  // IDB: linktype=1(ethernet), reserved=0, snaplen=65535
  push(0x00000001, [...u16(1), ...u16(0), ...u32(65535)])
  for (const p of packets) {
    const us = BigInt(p.tsUs)
    const hi = Number(us >> 32n)
    const lo = Number(us & 0xffffffffn)
    push(0x00000006, [...u32(0), ...u32(hi), ...u32(lo), ...u32(p.data.length), ...u32(p.data.length), ...p.data])
  }
  return Buffer.concat(blocks)
}

// ---- 构造报文 ----
const C = { ip: '192.168.1.10', mac: '00:11:22:33:44:55' }
const S = { ip: '93.184.216.34', mac: '00:aa:bb:cc:dd:ee' }
const D = { ip: '8.8.8.8', mac: '00:bb:cc:dd:ee:ff' }

const us = (t) => Math.round(t * 1_000_000) // 秒 → 微秒(绝对时间戳)

const pktHttp = ({ sport, dport, seq, ack, flags, payload, t }) => ({
  tsUs: us(t),
  data: eth(S.mac, C.mac, 0x0800, ip4hdr(C.ip, S.ip, 6, tcpseg(sport, dport, seq, ack, flags, payload))),
})
const pktHttpRev = ({ sport, dport, seq, ack, flags, payload, t }) => ({
  tsUs: us(t),
  data: eth(C.mac, S.mac, 0x0800, ip4hdr(S.ip, C.ip, 6, tcpseg(sport, dport, seq, ack, flags, payload))),
})

// HTTP 会话:握手 + GET + 200 + 正常关闭
const get = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pUI-test\r\n\r\n')
const ok = Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\nhello pUI')
const http = [
  pktHttp({ sport: 54321, dport: 80, seq: 1000, ack: 0, flags: SYN, t: 0.000 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5000, ack: 1001, flags: SYN | ACK, t: 0.032 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: ACK, t: 0.032 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: PSH | ACK, payload: [...get], t: 0.045 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5001, ack: 1001 + get.length, flags: ACK, t: 0.061 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5001, ack: 1001 + get.length, flags: PSH | ACK, payload: [...ok], t: 0.180 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001 + get.length, ack: 5001 + ok.length, flags: ACK, t: 0.181 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001 + get.length, ack: 5001 + ok.length, flags: ACK | FIN, t: 0.230 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5001 + ok.length, ack: 1001 + get.length + 1, flags: ACK, t: 0.262 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5001 + ok.length, ack: 1001 + get.length + 1, flags: ACK | FIN, t: 0.280 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001 + get.length + 1, ack: 5001 + ok.length + 1, flags: ACK, t: 0.290 }),
]

// 丢包示例:握手后发出 GET,服务器未 ACK,客户端重传(同 seq),随后无响应 → 重传+丢响应
const lossy = [
  pktHttp({ sport: 54321, dport: 80, seq: 1000, ack: 0, flags: SYN, t: 0.000 }),
  pktHttpRev({ sport: 80, dport: 54321, seq: 5000, ack: 1001, flags: SYN | ACK, t: 0.032 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: ACK, t: 0.032 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: PSH | ACK, payload: [...get], t: 0.045 }),
  pktHttp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: PSH | ACK, payload: [...get], t: 0.400 }),
]

// DNS 查询/响应(example.com A → 8.8.8.8)
const qname = [7, ...[...'example'].map((c) => c.charCodeAt(0)), 3, ...[...'com'].map((c) => c.charCodeAt(0)), 0]
const dnsQ = Buffer.from([...u16(0x1234), 0x01, 0x00, 0, 1, 0, 0, 0, 0, ...qname, 0, 1, 0, 1])
const dnsR = Buffer.from([...u16(0x1234), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...qname, 0, 1, 0, 1, ...u32(300), 0, 4, ...ip4('8.8.8.8')])
const dns = [
  { tsUs: us(0.000), data: eth(D.mac, C.mac, 0x0800, ip4hdr(C.ip, D.ip, 17, udpseg(54322, 53, [...dnsQ]))) },
  { tsUs: us(0.020), data: eth(C.mac, D.mac, 0x0800, ip4hdr(D.ip, C.ip, 17, udpseg(53, 54322, [...dnsR]))) },
]

// ARP 请求/应答
const arpReq = [0, 1, ...u16(0x0800), 6, 4, 0, 1, ...mac(C.mac), ...ip4(C.ip), 0, 0, 0, 0, 0, 0, ...ip4('192.168.1.1')]
const arpRep = [0, 1, ...u16(0x0800), 6, 4, 0, 2, ...mac('aa:aa:aa:aa:aa:aa'), ...ip4('192.168.1.1'), ...mac(C.mac), ...ip4(C.ip)]
const arp = [
  { tsUs: us(0.000), data: eth('ff:ff:ff:ff:ff:ff', C.mac, 0x0806, arpReq) },
  { tsUs: us(0.005), data: eth(C.mac, 'aa:aa:aa:aa:aa:aa', 0x0806, arpRep) },
]

// 写入
mkdirSync(join(OUT, 'examples'), { recursive: true })
writeFileSync(join(OUT, 'examples', 'http.pcapng'), pcapng(http))
writeFileSync(join(OUT, 'examples', 'dns.pcapng'), pcapng(dns))
writeFileSync(join(OUT, 'examples', 'mixed.pcapng'), pcapng([...arp, ...dns, ...http]))
writeFileSync(join(OUT, 'examples', 'lossy.pcapng'), pcapng(lossy))
console.log('generated:', join(OUT, 'examples'), 'http/dns/mixed/lossy')
