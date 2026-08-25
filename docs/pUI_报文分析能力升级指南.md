# pUI 报文分析能力升级指南

> 目标：把 pUI 从“PCAP/报文查看工具”逐步升级为“面向网络故障定位的 PCAP 分析工具”。
>
> 核心理念：**不是告诉用户“丢包了”，而是把报文转换成可验证的故障证据链。**

---

## 1. 项目定位

建议不要把 pUI 定位成“另一个 Wireshark”。

Wireshark 更擅长回答：

> 这个报文是什么？字段是什么？协议怎么解析？

pUI 可以重点回答：

> 这些报文组合起来说明发生了什么？  
> 为什么业务会卡？  
> 哪些证据支持这个判断？  
> 当前抓包条件下能够确定到什么程度？

最终形成：

```text
PCAP
  ↓
协议/字段解析
  ↓
Flow / TCP Stream
  ↓
异常检测
  ↓
事件还原
  ↓
证据链
  ↓
故障结论
  ↓
业务影响
  ↓
报告
```

---

# 2. 第一阶段：TCP 会话健康度

## 目标

用户打开 PCAP 后，不应该首先面对大量报文，而应该先看到 TCP 会话整体状态。

示例：

```text
TCP Stream 0

192.168.183.185:28511
        ↕
172.205.100.199:54529

Packets: 23,844
Bytes:   21 MB
Duration: 48.2s

TCP Health
────────────────────────
Retransmission       1305   ⚠
Fast Retransmission   883   ⚠
Duplicate ACK        2073   ⚠
Out-of-Order         1132   ⚠
Lost Segment          104   ⚠
Zero Window             0
RST                     0
```

## 建议统计指标

第一版至少支持：

- Retransmission
- Fast Retransmission
- Duplicate ACK
- SACK
- Out-of-Order
- Lost Segment
- Zero Window
- Window Full
- TCP Reset
- SYN Retransmission
- SYN/ACK Retransmission
- RTT
- RTT variation

## 注意

这些指标只能作为**证据**，不能直接等价于“网络丢包”。

例如：

```text
Retransmission ≠ 一定是网络丢包
Out-of-Order ≠ 丢包
Lost Segment ≠ 一定是真实网络丢包
```

---

# 3. 第二阶段：TCP Sequence Gap Detection

这是 TCP 分析的核心能力。

## 目标

自动检测：

> 接收端的 TCP 字节流是否存在缺口。

例如：

```text
ACK = 2204519

SACK:
2220449-2221817
2280949-2286421
2286627-2595982
```

工具应该自动转换为：

```text
TCP Sequence Space

2204519
   │
   │ ACK
   ▼
   │
   │ GAP
   ▼
2220449 ───── 2221817
                 │
                 │ GAP
                 ▼
2280949 ───── 2286421
                 │
                 │ GAP
                 ▼
2286627 ───────────── 2595982
```

## 需要计算

- Gap 起点
- Gap 终点
- Gap 大小
- 是否有后续 SACK
- Gap 是否最终被填补
- Gap 是否对应 Retransmission
- Gap 存续时间

---

# 4. 第三阶段：TCP Event Engine

这是 pUI 最值得重点投入的模块。

不要只统计：

```text
Retransmission = 1305
```

而要把相关报文组织成一个“事件”。

## 示例

```text
TCP Event #27

Original Segment
Packet #3200
Seq=2204519
Len=1368

        ↓

Duplicate ACK
Packet #3439
ACK=2204519

SACK:
2220449-2221817
2280949-2286421
2286627-2595982

        ↓

Duplicate ACK ×323

        ↓

Retransmission
Packet #4360
Seq=2204519

        ↓

Recovery ACK
Packet #4361
ACK=2205887
```

自动生成：

> 检测到一个 TCP Sequence Gap，后续数据已经通过 SACK 到达，接收端产生大量 Duplicate ACK，发送端随后重传缺失数据，最终 ACK 向前推进。

---

# 5. TCP 事件状态机

建议建立事件状态机，而不是简单依赖 Wireshark 的 analysis 标签。

## 典型“疑似丢包/未及时到达”

```text
Original Segment
      ↓
ACK 停滞
      ↓
Duplicate ACK
      ↓
SACK
      ↓
Retransmission
      ↓
ACK Forward
```

可以标记：

```text
Possible Loss / Delayed Segment
```

## 典型乱序

```text
Seq A
Seq C
Seq B
```

最终 B 到达：

```text
Out-of-Order
      ↓
Gap Filled
      ↓
No Retransmission
```

标记：

```text
Out-of-Order, no retransmission observed
```

## 可能的 ACK 丢失

```text
Data
 ↓
Receiver already received data
 ↓
Sender retransmits
 ↓
No meaningful data gap observed
```

可以标记：

```text
Possible ACK Loss / Spurious Retransmission
```

---

# 6. 必须区分的几个概念

pUI 的分析引擎不要简单做：

```text
Retransmission → Packet Loss
```

至少要区分：

| 现象 | 含义 |
|---|---|
| Retransmission | 发送端重新发送数据 |
| Fast Retransmission | 通常与 Duplicate ACK/SACK 有关 |
| Duplicate ACK | 接收端累计 ACK 没有前进 |
| SACK | 接收端报告已经收到的非连续数据块 |
| Out-of-Order | 数据到达顺序与序列号顺序不同 |
| Sequence Gap | 当前观察视角下存在字节流缺口 |
| Lost Segment | Wireshark 推断某段未在预期位置出现 |
| Spurious Retransmission | 可能是已经到达但 ACK 未被及时看到 |

最终结论应该是：

> “观察到了什么”

和：

> “推断发生了什么”

分开。

---

# 7. 单端抓包模式

这是实际网络故障中非常重要的能力。

如果只能在接收端抓包，工具应该明确显示：

```text
Capture Perspective

● Single-sided capture

⚠ 当前为单端抓包

可以判断：
✓ 接收端观察到的 Sequence Gap
✓ Duplicate ACK
✓ SACK
✓ Retransmission
✓ RTT/时延变化
✓ TCP 状态变化

不能完全判断：
✗ 丢包具体发生在哪个网络节点
✗ 发送端是否真正发出了某个包
✗ 中间交换机/路由器/防火墙是否丢包
✗ 抓包点本身是否漏包
```

## 结论措辞建议

不要：

> “交换机丢包。”

建议：

> “接收端抓包观察到 TCP 数据未按连续序列到达，随后出现 Duplicate ACK/SACK 及重传。当前证据支持数据未及时到达，但单端抓包无法定位具体丢包位置。”

---

# 8. 抓包本身可能漏包

分析引擎必须考虑：

> PCAP 自身是否不完整？

例如：

```text
Seq 1000
Seq 3000
```

不能立即判定：

> Seq 2000 在网络中丢了。

还需要考虑：

- 网卡抓包丢包
- ring buffer overflow
- tcpdump/libpcap 丢包
- 高负载抓包
- SnapLen
- 虚拟机抓包限制
- 镜像端口丢包
- 采集链路问题

如果能获得抓包接口统计信息，也应该纳入判断。

---

# 9. TCP Sequence Space 可视化

建议增加独立的 TCP Sequence Space View。

例如：

```text
TCP Sequence Space
──────────────────────────────────────────────>

2204519
   │
   │ ACK
   ▼
   │
   │ GAP
   │
   ├───────────────┐
                   │
                   ▼
              SACK Block
              2220449-2221817

              SACK Block
              2280949-2286421

              SACK Block
              2286627-2595982
```

鼠标悬停在 Gap 上时显示：

```text
Gap:
2205887 → 2220449

Estimated missing bytes:
1562

First observed:
Packet #3439

Filled by:
Packet #4360
```

---

# 10. “为什么这个包被标记为 Retransmission？”

建议在报文详情旁边增加：

```text
Why?

① Original Segment
   Packet #3200
   Seq=2204519
   Len=1368

② ACK State
   ACK=2204519

③ SACK
   Later segments already received

④ Duplicate ACK
   323 occurrences

⑤ Current Packet
   Seq=2204519
   Retransmission

Conclusion:
The retransmission is strongly correlated
with the observed TCP sequence gap.
```

这个功能可以帮助用户学习 TCP，而不仅仅是看结果。

---

# 11. TCP Incident Timeline

这是建议作为核心 UI 的功能。

例如：

```text
TCP Incident Timeline

3200
Data
Seq=2204519
   │
   ▼
3439
Duplicate ACK
ACK=2204519
SACK present
   │
   ▼
3440~...
Duplicate ACK ×323
   │
   ▼
4360
Retransmission
Seq=2204519
   │
   ▼
4361
ACK=2205887
Recovery
```

用户点击任意事件，可以跳转到对应 Packet。

---

# 12. 业务体验分析

在 TCP 分析稳定以后，可以逐步增加应用层分析。

第一批建议：

- VNC
- RDP
- SSH
- HTTP
- HTTPS（只能分析加密连接的 TCP/TLS 特征，不能解密业务内容）
- DNS
- SMB

例如 VNC：

```text
Application Experience

VNC
────────────────────

TCP connection        ✓
Authentication        ✓
Post-auth traffic     ⚠
TCP retransmission    ⚠
Sequence gaps         ⚠
Application response  delayed

Possible impact:
VNC login / desktop initialization
may be delayed by TCP transport anomalies.
```

---

# 13. 网络异常与业务异常关联

目标是形成：

```text
用户看到：
VNC 一直 Loading
       ↓
应用层：
登录/桌面初始化没有及时完成
       ↓
TCP：
大量 Dup ACK
SACK
Retransmission
Sequence Gap
       ↓
网络：
存在明显传输异常
```

注意：

不要直接声称：

> TCP 异常一定导致 VNC Loading。

应该使用：

> “时间和行为高度相关，TCP 传输异常可能影响应用层流程。”

如果存在完整时间线，再提高置信度。

---

# 14. TCP Health Score

可以提供：

```text
TCP Health Score

42 / 100
```

评分维度：

- Retransmission
- Fast Retransmission
- Duplicate ACK
- Sequence Gap
- Out-of-Order
- RTT
- RTT Variation
- Zero Window
- Reset
- Connection setup delay

但：

> Health Score 只用于快速筛选，不作为最终诊断结论。

---

# 15. Top TCP Events

打开一个 Stream 后，自动列出最值得关注的事件：

```text
Top TCP Events

#1  Sequence Gap
    Seq=2204519
    Dup ACK ×323
    SACK
    Retransmission
    Recovery

#2  Fast Retransmission
    Seq=...

#3  Large Out-of-Order
    Seq=...

#4  Zero Window
    ...
```

用户可以从“最严重/最有证据”的事件开始分析。

---

# 16. 报告导出

建议支持：

```text
Export
 ├── Markdown
 ├── HTML
 ├── JSON
 └── PDF（后续）
```

Markdown 示例：

```markdown
# TCP Stream Analysis Report

## Stream

192.168.183.185:28511
↔
172.205.100.199:54529

## Summary

- Packets: 23844
- Bytes: 21 MB
- Retransmission: 1305
- Fast Retransmission: 883
- Duplicate ACK: 2073
- Out-of-Order: 1132
- Lost Segment: 104

## Key Findings

Detected significant TCP transport anomalies.

## Event #27

Original:
- Packet: 3200
- Seq: 2204519
- Len: 1368

Duplicate ACK:
- Packet: 3439
- ACK: 2204519
- SACK present

Retransmission:
- Packet: 4360
- Seq: 2204519

Recovery:
- Packet: 4361
- ACK: 2205887

## Conclusion

The receiver observed a TCP sequence gap followed by
Duplicate ACK/SACK and retransmission.

Because this is a single-sided capture, the exact
network location of packet loss cannot be determined.
```

---

# 17. JSON 数据模型

建议内部不要让 UI 直接依赖 Wireshark 的显示字符串。

建立自己的结构化模型。

例如：

```json
{
  "stream": 0,
  "endpoints": {
    "a": "192.168.183.185:28511",
    "b": "172.205.100.199:54529"
  },
  "metrics": {
    "retransmissions": 1305,
    "fast_retransmissions": 883,
    "duplicate_acks": 2073,
    "out_of_order": 1132,
    "lost_segments": 104
  },
  "events": [
    {
      "type": "sequence_gap",
      "seq": 2204519,
      "length": 1368,
      "original_packet": 3200,
      "duplicate_ack_count": 323,
      "sack": [
        [2220449, 2221817],
        [2280949, 2286421],
        [2286627, 2595982]
      ],
      "retransmission_packet": 4360,
      "recovery_ack_packet": 4361
    }
  ]
}
```

这样后续：

```text
UI
AI
Report
CLI
API
```

都可以复用同一套分析结果。

---

# 18. AI 应该放在哪里？

不要让 AI 直接从几十万条 Packet 猜答案。

推荐：

```text
PCAP
 ↓
Parser
 ↓
Flow Builder
 ↓
TCP State Engine
 ↓
Event Detection
 ↓
Evidence JSON
 ↓
AI
 ↓
Human-readable Explanation
```

AI 的职责：

- 解释事件
- 总结故障
- 生成报告
- 把 TCP 术语翻译成人话
- 根据证据提出下一步排查建议

而不是：

> “凭感觉判断丢包。”

---

# 19. 推荐架构

可以逐步形成：

```text
pUI
│
├── Capture / PCAP Reader
│
├── Protocol Parser
│
├── Flow Engine
│
├── TCP Engine
│   ├── Seq Tracker
│   ├── ACK Tracker
│   ├── SACK Tracker
│   ├── RTT Calculator
│   ├── Retransmission Detector
│   ├── Dup ACK Detector
│   ├── OOO Detector
│   └── Gap Detector
│
├── Event Engine
│   ├── Loss Event
│   ├── Reordering Event
│   ├── ACK Loss Event
│   ├── Zero Window Event
│   └── Connection Event
│
├── Application Analyzer
│   ├── VNC
│   ├── RDP
│   ├── SSH
│   └── HTTP
│
├── Evidence Engine
│
├── Report Engine
│
└── UI
    ├── Overview
    ├── Flow
    ├── TCP Timeline
    ├── Sequence Space
    ├── Packet Detail
    └── Report
```

---

# 20. 推荐开发路线

## V0.1

先实现：

- PCAP 打开
- TCP Stream 列表
- TCP 基础统计
- Retransmission
- Duplicate ACK
- Out-of-Order
- SACK
- Lost Segment

## V0.2

实现：

- Sequence Gap Detection
- TCP Sequence Tracker
- ACK Tracker
- SACK Tracker

## V0.3

实现：

- TCP Event Engine
- Event Timeline
- Retransmission Cause Analysis
- Loss / Reorder / ACK Loss 分类

## V0.4

实现：

- Sequence Space Visualization
- SACK Visualization
- TCP Health Score
- Top Events

## V0.5

实现：

- Markdown / JSON 报告
- 单端抓包提示
- Capture Loss 风险提示

## V0.6

实现：

- VNC / RDP / SSH 等业务分析
- Application Experience

## V1.0

形成：

> **PCAP → 网络故障证据链 → 自动分析报告**

---

# 21. 最重要的设计原则

### 原则 1：证据优先

```text
Evidence
  >
Inference
  >
Conclusion
```

### 原则 2：不要把 Wireshark 标签当最终答案

```text
Retransmission
```

只是一个现象。

真正有价值的是：

```text
为什么重传？
之前发生了什么？
接收端 ACK 到哪里？
有没有 SACK？
有没有 Gap？
重传后是否恢复？
```

### 原则 3：区分“观察”和“推断”

推荐 UI：

```text
Observed
✓ Duplicate ACK ×323
✓ SACK present
✓ Sequence gap
✓ Retransmission

Inference
⚠ Possible packet loss / delayed segment

Limitation
⚠ Single-sided capture
```

### 原则 4：先规则，后 AI

TCP 基础判断应该尽量由确定性的规则/状态机完成。

AI 负责解释，不负责替代 TCP 状态机。

---

# 22. pUI 最终可以形成的核心能力

最终用户打开一个 PCAP，不需要自己从：

```text
3200
3439
4360
4361
```

一点一点寻找。

pUI 可以直接告诉他：

```text
TCP Stream 0
────────────────────────────

⚠ Significant TCP Transport Anomaly

Key Event #27
────────────────────────────
Sequence Gap
    ↓
Duplicate ACK ×323
    ↓
SACK
    ↓
Retransmission
    ↓
ACK Recovery

Impact
────────────────────────────
Potential application delay

Capture Limitation
────────────────────────────
Single-sided capture:
exact loss location cannot be determined.
```

然后用户点击“查看证据”，才进入具体报文。

这会让 pUI 从：

> **Packet Viewer**

真正变成：

> **Network Troubleshooting Assistant**

---

# 23. 一句话产品目标

建议把整个项目的设计方向浓缩成：

> **把 PCAP 中分散的报文，自动还原成可验证的网络故障事件和证据链。**

这也是后续所有功能取舍的判断标准。

如果一个功能只是“让用户看到更多字段”，优先级可以低一些。

如果一个功能能够：

> **让用户更快回答“发生了什么、为什么发生、证据在哪里、还能不能继续定位”**

那么它就是 pUI 的核心能力。
