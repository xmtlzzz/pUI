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

// M6 第二批演示:SSH/VNC/RDP/SMB2 各一条真实握手流(加密边界内只暴露明文握手/命令字段)
const R1 = { ip: '192.168.1.20', mac: '00:22:33:44:55:66' } // sshd + vnc server
const R2 = { ip: '192.168.1.30', mac: '00:33:44:55:66:77' } // rdp + smb server

const pktTo = (dst, { sport, dport, seq, ack, flags, payload, t }) => ({
  tsUs: us(t),
  data: eth(dst.mac, C.mac, 0x0800, ip4hdr(C.ip, dst.ip, 6, tcpseg(sport, dport, seq, ack, flags, payload))),
})
const pktFrom = (dst, { sport, dport, seq, ack, flags, payload, t }) => ({
  tsUs: us(t),
  data: eth(C.mac, dst.mac, 0x0800, ip4hdr(dst.ip, C.ip, 6, tcpseg(sport, dport, seq, ack, flags, payload))),
})
const utf8 = (s) => Buffer.from(s, 'utf-8')
const utf16le = (s) => Buffer.from(s, 'utf-16le')
const handshake = (dport, sport, server, t0) => [
  pktTo(server, { sport, dport, seq: 1000, ack: 0, flags: SYN, t: t0 }),
  pktFrom(server, { sport: dport, dport: sport, seq: 5000, ack: 1001, flags: SYN | ACK, t: t0 + 0.001 }),
  pktTo(server, { sport, dport, seq: 1001, ack: 5001, flags: ACK, t: t0 + 0.002 }),
]
const close = (server, dport, sport, seqC, seqS, t0) => [
  pktTo(server, { sport, dport, seq: seqC, ack: seqS, flags: ACK | FIN, t: t0 }),
  pktFrom(server, { sport: dport, dport: sport, seq: seqS, ack: seqC + 1, flags: ACK | FIN, t: t0 + 0.001 }),
  pktTo(server, { sport, dport, seq: seqC + 1, ack: seqS + 1, flags: ACK, t: t0 + 0.002 }),
]

// SSH(22):双方版本横幅(明文)→ 此后加密(演示解密边界)
const sshClientBanner = utf8('SSH-2.0-OpenSSH_9.6\r\n')
const sshServerBanner = utf8('SSH-2.0-OpenSSH_8.4\r\n')
const ssh = [
  ...handshake(22, 52022, R1, 0.0),
  pktTo(R1, { sport: 52022, dport: 22, seq: 1001, ack: 5001, flags: PSH | ACK, payload: [...sshClientBanner], t: 0.010 }),
  pktFrom(R1, { sport: 22, dport: 52022, seq: 5001, ack: 1001 + sshClientBanner.length, flags: PSH | ACK, payload: [...sshServerBanner], t: 0.020 }),
  // 横幅交换后的密钥交换载荷:对分析器是字节噪声(红线:不解密,只证明「此后密文」)
  pktTo(R1, { sport: 52022, dport: 22, seq: 1001 + sshClientBanner.length, ack: 5001 + sshServerBanner.length, flags: PSH | ACK, payload: [0x05, 0x14, 0x7c, 0x11, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x6d], t: 0.030 }),
  ...close(R1, 22, 52022, 1011 + sshClientBanner.length, 5001 + sshServerBanner.length, 0.050),
]

// VNC(5900):RFB 版本 + 安全类型列表(1=无认证 2=VNC 密码)+ 客户端选择
const vnc = [
  ...handshake(5900, 51900, R1, 0.100),
  pktFrom(R1, { sport: 5900, dport: 51900, seq: 5001, ack: 1001, flags: PSH | ACK, payload: [...utf8('RFB 003.008\n')], t: 0.110 }),
  // 安全类型列表:数量 2,类型 1(无认证)、2(VNC 密码)
  pktFrom(R1, { sport: 5900, dport: 51900, seq: 5001 + 12, ack: 1001, flags: PSH | ACK, payload: [0x02, 0x01, 0x02], t: 0.112 }),
  // 客户端选择类型 1(无认证)
  pktTo(R1, { sport: 51900, dport: 5900, seq: 1001, ack: 5001 + 15, flags: PSH | ACK, payload: [0x01], t: 0.114 }),
  ...close(R1, 5900, 51900, 1002, 5001 + 15, 0.130),
]

// RDP(3389):X.224 连接请求/确认携带 RDP 协商(0x3=SSL+CredSSP → 0x2=CredSSP)
const rdpCR = [0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]
const rdpCC = [0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]
const rdp = [
  ...handshake(3389, 51800, R2, 0.200),
  pktTo(R2, { sport: 51800, dport: 3389, seq: 1001, ack: 5001, flags: PSH | ACK, payload: rdpCR, t: 0.210 }),
  pktFrom(R2, { sport: 3389, dport: 51800, seq: 5001, ack: 1001 + rdpCR.length, flags: PSH | ACK, payload: rdpCC, t: 0.220 }),
  ...close(R2, 3389, 51800, 1001 + rdpCR.length, 5001 + rdpCC.length, 0.240),
]

// SMB2(445):协商 → 树连接。SMB2 多字节字段一律小端(与 TCP 头大端相反)。
const u16le = (n) => [n & 0xff, (n >> 8) & 0xff]
const u32le = (n) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
const smb2hdr = (cmd, flags, messageId, treeId = 0) => [
  0xfe, 0x53, 0x4d, 0x42, // ProtocolId: 0xFE + 'SMB'(服务器模式标识)
  ...u16le(64), ...u16le(0), ...u32le(0), // StructureSize=64, CreditCharge, Status
  ...u16le(cmd), ...u16le(0), ...u32le(flags), // Command, Credits, Flags(bit0=响应)
  ...u32le(0), // NextCommand
  ...u32le(messageId), ...u32le(0), // MessageId(8B)
  ...u32le(0), // Reserved/ProcessId
  ...u32le(treeId), // TreeId
  ...u32le(0), ...u32le(0), // SessionId(8B)
  ...Array(16).fill(0), // Signature
]
const nb = (body) => [0x00, ...u32(body.length).slice(1), ...body] // NetBIOS 会话:1B 类型 + 3B 长度(大端)
const smbNegReq = [...nb([...smb2hdr(0, 0, 0), ...u16le(36), ...u16le(2), ...u16le(1), ...u16le(0), ...u32le(0), ...Array(16).fill(0x11), ...u16le(0), ...u16le(0), ...u16le(0), ...u16le(0x0202), ...u16le(0x0210)])]
const smbNegRsp = [...nb([...smb2hdr(0, 1, 1), ...u16le(65), ...u16le(2), ...u16le(1), ...u16le(0), ...u32le(0), ...Array(16).fill(0x22), ...u16le(0), ...u16le(0), ...u16le(0), ...u16le(0x0202), ...u16le(0x0210), ...u32le(0)])]
const treePath = utf16le('\\\\DEMO\\share') // UNC: \\DEMO\share
const smbTreeReq = [...nb([...smb2hdr(3, 0, 2), ...u16le(9), ...u16le(0), ...u16le(72), ...u16le(treePath.length), ...treePath])]
const smbTreeRsp = [...nb([...smb2hdr(3, 1, 3, 1), ...u16le(16), ...u16le(0), ...u32le(0), ...u32le(0)])]
const smb2 = [
  ...handshake(445, 51700, R2, 0.300),
  pktTo(R2, { sport: 51700, dport: 445, seq: 1001, ack: 5001, flags: PSH | ACK, payload: smbNegReq, t: 0.310 }),
  pktFrom(R2, { sport: 445, dport: 51700, seq: 5001, ack: 1001 + smbNegReq.length, flags: PSH | ACK, payload: smbNegRsp, t: 0.320 }),
  pktTo(R2, { sport: 51700, dport: 445, seq: 1001 + smbNegReq.length, ack: 5001 + smbNegRsp.length, flags: PSH | ACK, payload: smbTreeReq, t: 0.330 }),
  pktFrom(R2, { sport: 445, dport: 51700, seq: 5001 + smbNegRsp.length, ack: 1001 + smbNegReq.length + smbTreeReq.length, flags: PSH | ACK, payload: smbTreeRsp, t: 0.340 }),
  ...close(R2, 445, 51700, 1001 + smbNegReq.length + smbTreeReq.length, 5001 + smbNegRsp.length + smbTreeRsp.length, 0.360),
]

const remote = [...ssh, ...vnc, ...rdp, ...smb2]

// 写入
mkdirSync(join(OUT, 'examples'), { recursive: true })
writeFileSync(join(OUT, 'examples', 'http.pcapng'), pcapng(http))
writeFileSync(join(OUT, 'examples', 'dns.pcapng'), pcapng(dns))
writeFileSync(join(OUT, 'examples', 'mixed.pcapng'), pcapng([...arp, ...dns, ...http]))
writeFileSync(join(OUT, 'examples', 'lossy.pcapng'), pcapng(lossy))
writeFileSync(join(OUT, 'examples', 'remote.pcapng'), pcapng(remote))
console.log('generated:', join(OUT, 'examples'), 'http/dns/mixed/lossy/remote')
