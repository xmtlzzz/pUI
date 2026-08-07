import type { Conversation, FilterCondition, FilterOptions, Packet } from '../model/types'

export function filterConversations(convs: Conversation[], cond: FilterCondition): Conversation[] {
  const pass = (c: Conversation): boolean => {
    if (cond.protocol.length && !c.packets.some((p) => cond.protocol.includes(p.proto))) return false
    if (cond.srcIp.length && !c.packets.some((p) => p.srcIp != null && cond.srcIp.includes(p.srcIp))) return false
    if (cond.dstIp.length && !c.packets.some((p) => p.dstIp != null && cond.dstIp.includes(p.dstIp))) return false
    if (cond.srcPort.length && !c.packets.some((p) => p.srcPort != null && cond.srcPort.includes(p.srcPort))) return false
    if (cond.dstPort.length && !c.packets.some((p) => p.dstPort != null && cond.dstPort.includes(p.dstPort))) return false
    return true
  }
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
    if (p.dstIp) dstIps.add(p.dstIp)
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
