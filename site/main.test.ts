// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import html from "./index.html?raw";
import { fireEvent } from "@testing-library/dom";
import { createDemo, packetDetail, selectConversation } from "./demo";

beforeEach(async () => {
  vi.resetModules();
  document.documentElement.innerHTML = html;
  await import("./main");
});

describe("官网交互示例", () => {
  it("首屏显示真实合成抓包统计与选中报文，未上传用户文件", () => {
    const demo = createDemo("lossy");
    expect(document.querySelector("#capture-summary")?.textContent).toBe(
      `${demo.packets.length} 个报文 · ${demo.conversations.length} 个会话`,
    );
    expect(
      document.querySelector('[data-packet][aria-pressed="true"]'),
    ).not.toBeNull();
    expect(document.querySelector('input[type="file"]')).toBeNull();
  });

  it("切换 DNS 清除上个示例的会话、报文和 TCP 字段", () => {
    fireEvent.click(document.querySelector('[data-sample="dns"]')!);
    const demo = createDemo("dns");
    expect(document.querySelector("#file-label")?.textContent).toBe(
      "dns.pcapng",
    );
    expect(document.querySelectorAll("[data-conversation]")).toHaveLength(
      demo.conversations.length,
    );
    expect(document.querySelectorAll("[data-packet]")).toHaveLength(
      selectConversation(demo)!.packets.length,
    );
    expect(document.querySelector("#packet-detail")?.textContent).toContain(
      "Seq: unavailable",
    );
    expect(
      document
        .querySelector('[data-sample="dns"]')
        ?.getAttribute("aria-pressed"),
    ).toBe("true");
    expect(
      document
        .querySelector('[data-sample="lossy"]')
        ?.getAttribute("aria-pressed"),
    ).toBe("false");
  });

  it("点选另一帧展示该帧的完整字段而非固定演示文本", () => {
    fireEvent.click(document.querySelector('[data-sample="http"]')!);
    const packets = selectConversation(createDemo("http"))!.packets;
    const last = packets[packets.length - 1];
    fireEvent.click(document.querySelector(`[data-packet="${last.number}"]`)!);
    expect(document.querySelector("#packet-detail")?.textContent).toBe(
      packetDetail(last),
    );
    expect(
      document.querySelectorAll('[data-packet][aria-pressed="true"]'),
    ).toHaveLength(1);
  });

  it("功能介绍中的示例入口切换到对应数据", () => {
    fireEvent.click(document.querySelector('[data-jump-sample="http"]')!);
    expect(document.querySelector("#file-label")?.textContent).toBe(
      "http.pcapng",
    );
  });
});
