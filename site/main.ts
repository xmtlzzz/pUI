import {
  createDemo,
  demoLabels,
  packetDetail,
  selectConversation,
  type DemoName,
} from "./demo";
import type { Conversation, Packet } from "../src/model/types";

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing website element: ${id}`);
  return found as T;
}

let demo = createDemo("lossy");
let conversation = selectConversation(demo);
let selectedPacket = 0;

function text(tag: string, value: string, className?: string): HTMLElement {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function showPacket(packet: Packet) {
  selectedPacket = packet.number;
  element("packet-detail").textContent = packetDetail(packet);
  const tags = packet.tcpAnalysis ?? [];
  element("packet-tags").replaceChildren(
    ...(tags.length
      ? tags.map((tag) => text("span", tag))
      : [text("span", "未观察到 TCP 异常标签", "no-tags")]),
  );
  element("inference-note").textContent = tags.length
    ? "异常标签是分析线索，不能仅凭标签断言路径丢包。完整事件推断见桌面版。"
    : "本帧字段可作为交互证据，完整结论需要结合会话上下文。";
  for (const button of document.querySelectorAll<HTMLButtonElement>(
    "[data-packet]",
  )) {
    button.setAttribute(
      "aria-pressed",
      String(Number(button.dataset.packet) === selectedPacket),
    );
  }
}

function showConversation(current: Conversation) {
  conversation = current;
  element("client-address").textContent = current.client;
  element("server-address").textContent = current.server;
  for (const button of document.querySelectorAll<HTMLButtonElement>(
    "[data-conversation]",
  )) {
    button.setAttribute(
      "aria-pressed",
      String(button.dataset.conversation === current.id),
    );
  }
  const rows = current.packets.map((packet) => {
    const button = document.createElement("button");
    button.type = "button";
    const fromClient = `${packet.srcIp}:${packet.srcPort}` === current.client;
    button.className = `packet-row${fromClient ? "" : " reverse"}${packet.tcpAnalysis?.length ? " anomaly" : ""}`;
    button.dataset.packet = String(packet.number);
    button.setAttribute(
      "aria-label",
      `查看帧 #${packet.number}：${packet.info ?? packet.proto}`,
    );
    button.setAttribute("aria-pressed", "false");
    const line = text("span", "", "packet-line");
    line.append(text("span", packet.info ?? packet.proto.toUpperCase()));
    button.append(
      text("span", `#${packet.number}`, "packet-number"),
      line,
      text("span", `${(packet.time * 1000).toFixed(0)} ms`, "packet-time"),
    );
    button.addEventListener("click", () => showPacket(packet));
    return button;
  });
  element("packet-sequence").replaceChildren(...rows);
  const first =
    current.packets.find((p) => p.tcpAnalysis?.length) ?? current.packets[0];
  if (first) showPacket(first);
}

function showDemo(name: DemoName) {
  demo = createDemo(name);
  element("file-label").textContent = `${name}.pcapng`;
  element("session-count").textContent = String(demo.conversations.length);
  element("capture-summary").textContent =
    `${demo.packets.length} 个报文 · ${demo.conversations.length} 个会话`;
  for (const button of document.querySelectorAll<HTMLButtonElement>(
    "[data-sample]",
  )) {
    button.setAttribute("aria-pressed", String(button.dataset.sample === name));
  }
  const sessions = demo.conversations.map((current) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "session";
    button.dataset.conversation = current.id;
    button.setAttribute(
      "aria-label",
      `查看 ${current.protocol.toUpperCase()} 会话：${current.client} → ${current.server}`,
    );
    button.setAttribute("aria-pressed", "false");
    const title = text("span", "", "session-title");
    title.append(
      text("span", current.protocol.toUpperCase()),
      text(
        "span",
        current.issues.length ? "存在观察线索" : "示例会话",
        current.issues.length ? undefined : "clean",
      ),
    );
    const route = text("span", "", "session-route");
    route.append(
      text("span", current.client),
      text("span", `→ ${current.server}`),
    );
    button.append(
      title,
      route,
      text(
        "small",
        `${current.packetCount} 个报文 · ${(current.duration * 1000).toFixed(0)} ms`,
      ),
    );
    button.addEventListener("click", () => showConversation(current));
    return button;
  });
  element("sessions").replaceChildren(...sessions);
  conversation = selectConversation(demo);
  if (conversation) showConversation(conversation);
}

function isDemoName(value: string | undefined): value is DemoName {
  return (
    value !== undefined &&
    Object.prototype.hasOwnProperty.call(demoLabels, value)
  );
}

for (const button of document.querySelectorAll<HTMLButtonElement>(
  "[data-sample]",
)) {
  button.addEventListener("click", () => {
    if (isDemoName(button.dataset.sample)) showDemo(button.dataset.sample);
  });
}
for (const link of document.querySelectorAll<HTMLAnchorElement>(
  "[data-jump-sample]",
)) {
  link.addEventListener("click", () => {
    if (isDemoName(link.dataset.jumpSample)) showDemo(link.dataset.jumpSample);
  });
}
showDemo("lossy");
