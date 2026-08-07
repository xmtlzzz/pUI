export type Direction = 'request' | 'response' | 'other'
export type Transport = 'tcp' | 'udp' | 'icmp' | 'arp' | 'other'

export interface Packet {
  number: number
  time: number // frame.time_relative 秒
  len: number // frame.len 字节
  transport: Transport
  proto: string // 应用层协议:http / dns / tls / tcp / udp / icmp / arp ...
  srcIp?: string
  dstIp?: string
  srcMac?: string
  dstMac?: string
  srcPort?: number
  dstPort?: number
  tcpFlags?: string // "0x0012"
  tcpSeq?: number
  tcpAck?: number
  httpMethod?: string
  httpUri?: string
  httpCode?: string
  dnsQuery?: string
  tlsType?: string
  info?: string // 概要,如 "HTTP GET /"、"TCP SYN-ACK"
  direction: Direction
}

export interface Conversation {
  id: string
  client: string // "ip:port" 或 "ip" 或 "mac"
  server: string
  protocol: string // 会话主协议
  packetCount: number
  bytes: number
  start: number
  end: number
  duration: number
  packets: Packet[] // 按 time 升序
}

export interface FilterCondition {
  protocol: string[]
  srcIp: string[]
  dstIp: string[]
  srcPort: number[]
  dstPort: number[]
  negate: boolean
}

export function emptyFilter(): FilterCondition {
  return { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false }
}

export interface FilterOptions {
  protocols: string[]
  srcIps: string[]
  dstIps: string[]
  ports: number[]
}

export interface CaptureMeta {
  fileName: string
  packetCount: number
  interfaces: number
  timeStart: number
  timeEnd: number
  fileSize: number
}
