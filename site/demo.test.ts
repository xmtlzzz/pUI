import { describe, expect, it } from "vitest";
import { createDemo, packetDetail, selectConversation } from "./demo";

describe("官网合成抓包示例", () => {
  it.each(["lossy", "http", "dns"] as const)(
    "%s 以产品解析器还原完整抓包，帧号唯一且会话不丢包",
    (name) => {
      const demo = createDemo(name);
      expect(demo.packets.length).toBeGreaterThan(0);
      expect(new Set(demo.packets.map((p) => p.number)).size).toBe(
        demo.packets.length,
      );
      expect(
        demo.conversations
          .flatMap((c) => c.packets)
          .map((p) => p.number)
          .sort((a, b) => a - b),
      ).toEqual(demo.packets.map((p) => p.number).sort((a, b) => a - b));
    },
  );

  it("默认选中异常会话，选中帧能回到原始报文字段", () => {
    const demo = createDemo("lossy");
    const conversation = selectConversation(demo);
    expect(conversation?.issues.length).toBeGreaterThan(0);
    for (const packet of conversation!.packets) {
      const detail = packetDetail(packet);
      expect(detail).toContain(`#${packet.number}`);
      expect(detail).toContain(`${packet.len} B`);
    }
  });

  it("切换会话只展示该会话，未知 id 不伪造结果", () => {
    const demo = createDemo("lossy");
    for (const conversation of demo.conversations) {
      expect(selectConversation(demo, conversation.id)).toBe(conversation);
    }
    expect(selectConversation(demo, "missing")).toBeUndefined();
  });

  it("非 TCP 字段明确标注不可用，不编造序列号或确认号", () => {
    const packet = createDemo("dns").packets[0];
    expect(packet.tcpSeq).toBeUndefined();
    expect(packetDetail(packet)).toContain("Seq: unavailable");
    expect(packetDetail(packet)).toContain("Ack: unavailable");
  });

  it("同一示例生成确定性结果", () => {
    expect(createDemo("lossy")).toEqual(createDemo("lossy"));
  });
});
