import { parsePackets } from "../src/parse/parsePackets";
import { aggregateConversations } from "../src/aggregate/aggregateConversations";
import type { Conversation, Packet } from "../src/model/types";
import lossy from "../public/fixtures/examples/parsed/lossy.json";
import http from "../public/fixtures/examples/parsed/http.json";
import dns from "../public/fixtures/examples/parsed/dns.json";

export type DemoName = "lossy" | "http" | "dns";
const fixtures = { lossy, http, dns };
export const demoLabels: Record<DemoName, string> = {
  lossy: "TCP 重传",
  http: "HTTP 请求",
  dns: "DNS 查询",
};

export function createDemo(name: DemoName) {
  const packets = parsePackets(JSON.stringify(fixtures[name]));
  return { name, packets, conversations: aggregateConversations(packets) };
}

export function selectConversation(
  demo: ReturnType<typeof createDemo>,
  id?: string,
): Conversation | undefined {
  if (id !== undefined) return demo.conversations.find((c) => c.id === id);
  return (
    demo.conversations.find((c) => c.issues.length > 0) ?? demo.conversations[0]
  );
}

export function packetDetail(packet: Packet): string {
  return `帧 #${packet.number} · ${packet.len} B\n时间: +${packet.time.toFixed(6)} s\n协议: ${packet.proto.toUpperCase()}\n源: ${packet.srcIp ?? "unavailable"}${packet.srcPort != null ? `:${packet.srcPort}` : ""}\n目的: ${packet.dstIp ?? "unavailable"}${packet.dstPort != null ? `:${packet.dstPort}` : ""}\nSeq: ${packet.tcpSeq ?? "unavailable"}\nAck: ${packet.tcpAck ?? "unavailable"}\n${packet.info ?? "摘要: unavailable"}`;
}
