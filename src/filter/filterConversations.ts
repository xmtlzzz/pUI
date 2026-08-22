import type { Conversation, FilterCondition, FilterOptions, Packet } from '../model/types'

export function filterConversations(convs: Conversation[], cond: FilterCondition): Conversation[] {
  const issueTypes = cond.issueTypes ?? []
  const pass = (c: Conversation): boolean => {
    if (cond.issueOnly && c.issues.length === 0) return false
    if (issueTypes.length && !c.issues.some((i) => issueTypes.includes(i.type))) return false
    if (cond.protocol.length && !c.packets.some((p) => cond.protocol.includes(p.proto))) return false
    if (cond.srcIp.length && !c.packets.some((p) => (p.srcIp != null && cond.srcIp.includes(p.srcIp)) || (p.srcMac != null && cond.srcIp.includes(p.srcMac)))) return false
    if (cond.dstIp.length && !c.packets.some((p) => (p.dstIp != null && cond.dstIp.includes(p.dstIp)) || (p.dstMac != null && cond.dstIp.includes(p.dstMac)))) return false
    if (cond.srcPort.length && !c.packets.some((p) => p.srcPort != null && cond.srcPort.includes(p.srcPort))) return false
    if (cond.dstPort.length && !c.packets.some((p) => p.dstPort != null && cond.dstPort.includes(p.dstPort))) return false
    return true
  }
  // 无任何筛选条件时,取反是"不筛选"的取反,应保留全部而非清空
  const hasCriteria =
    cond.protocol.length > 0 ||
    cond.srcIp.length > 0 ||
    cond.dstIp.length > 0 ||
    cond.srcPort.length > 0 ||
    cond.dstPort.length > 0 ||
    cond.issueOnly ||
    issueTypes.length > 0
  if (!hasCriteria) return convs
  return convs.filter((c) => (cond.negate ? !pass(c) : pass(c)))
}

export function collectFilterOptions(packets: Packet[]): FilterOptions {
  const protocols = new Set<string>()
  const srcIps = new Set<string>()
  const dstIps = new Set<string>()
  const ports = new Set<number>()
  for (const p of packets) {
    protocols.add(p.proto)
    if (p.srcIp) srcIps.add(p.srcIp)
    if (p.srcMac) srcIps.add(p.srcMac) // ARP 等非 IP 帧可按 MAC 筛选
    if (p.dstIp) dstIps.add(p.dstIp)
    if (p.dstMac) dstIps.add(p.dstMac)
    if (p.srcPort != null) ports.add(p.srcPort)
    if (p.dstPort != null) ports.add(p.dstPort)
  }
  return {
    protocols: [...protocols].sort(),
    srcIps: [...srcIps].sort(),
    dstIps: [...dstIps].sort(),
    ports: [...ports].sort((a, b) => a - b),
  }
}
