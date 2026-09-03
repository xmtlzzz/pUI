import type { Packet } from '../model/types'

/**
 * 时间流(flow)形态的时序图布局:纵轴 = 时间(从上往下),左侧时间刻度列,
 * 两条垂直生命线(左=客户端 / 右=服务端),每个报文一行水平箭头。
 * 与对角线形式(layout.ts)的本质区别:行内 y 由序号决定而非斜线延伸,
 * 视觉上等价于 tcp 故障分析里的「时间轴流」画法。
 *
 * 纯函数 + 确定性(同输入同输出,O(n));组件只负责把结果映射为 SVG 元素。
 */

/** DOM 行数上限:超量截断,分段导航由父层(segmentConversation)负责,
 *  这里只兜底防 DOM 爆炸(2000 与 SequenceDiagram 抽稀护栏同档) */
export const MAX_FLOW_ROWS = 2000

/** 时间流方向:请求(客户端→服务端)向右,响应向左,判不了用中性短横线 */
export type FlowDir = 'a2b' | 'b2a' | 'neutral'

export interface FlowRow {
  /** 帧号(Packet.number),点击回调与高亮都以它为键 */
  number: number
  /** 行中心 y(SVG 坐标,未乘 zoom;viewBox 盒尺寸模式与 SequenceDiagram 一致) */
  y: number
  dir: FlowDir
  /** 「#帧号 协议概要 · 长度」行内标注(拼装完成,组件直接渲染) */
  label: string
  /** 相对时刻(秒,Packet.time 原值) */
  time: number
  /** 时刻文本(三位小数,左侧时间刻度列渲染用) */
  timeLabel: string
  /** 绝对时刻 epoch 秒;缺失(undefined)时组件回退相对秒 */
  timeEpoch?: number
  /** frame.len 字节 */
  len: number
  proto: string
  /** 报文概要(Packet.info),可能与 label 重复但保留原值便于 tooltip */
  info: string
  /** tcpAnalysis 非空 = 观察到异常现象,整行视觉强调(浅红底/橙色帧号);
   *  红线:观察层标注 ≠ 结论,强调只为快速定位,不给因果判断 */
  anomaly: boolean
}

/** 左侧时间刻度列的一项(抽稀后每 tickEvery 行留一个,首行保底) */
export interface FlowTick {
  /** 对应 FlowRow 在 rows 数组中的下标(渲染时直接取 y) */
  rowIndex: number
  timeLabel: string
  timeEpoch?: number
}

export interface FlowLayout {
  rows: FlowRow[]
  ticks: FlowTick[]
  /** 画布宽(SVG viewBox 宽,与 layoutSequence 的 520 同档) */
  width: number
  /** 画布总高 = 顶部预留 + 行数×行高 + 底部留白 */
  height: number
  /** 单行高度(组件渲染箭头/文字时用同一常量对齐) */
  rowHeight: number
  /** 顶部预留(端点标签区,与 layout.HEADER_H 语义一致) */
  headerHeight: number
  /** 截断提示:true = rows 是原始报文的子集 */
  truncated: boolean
  /** 原始报文总数(截断提示「共 N 包」用) */
  total: number
}

export interface FlowLayoutOptions {
  /** 会话客户端端点("ip:port");'other' 方向按 srcIp 是否等于其主机部分判定 */
  client: string
  /** 会话服务端端点;同上,'other' 且 srcIp 匹配 server → b2a */
  server?: string
  /** 刻度抽稀密度:每 tickEvery 行输出一个时间刻度;缺省 1(全量,短会话不抽稀) */
  tickEvery?: number
  /** DOM 行数上限,缺省 MAX_FLOW_ROWS */
  maxRows?: number
}

// —— 画布几何常量:导出供组件与测试共用,保证布局↔渲染单一定义 ——
/** 左侧时间刻度列宽(三位小数 + 边距) */
export const TIME_COL_X = 56
/** 客户端生命线 x */
export const FLOW_CLIENT_X = 110
/** 服务端生命线 x */
export const FLOW_SERVER_X = 470
/** 顶部端点标签区高度(端点名标注在生命线顶部) */
export const FLOW_HEADER_H = 36
/** 首行 y = 标签区下留一档呼吸空间 */
const FIRST_ROW_TOP = FLOW_HEADER_H + 16
const ROW_H = 26
// 底部留白取整行高:末行(含其下沿文字)完整落在画布内,高度公式恒为 lastY + ROW_H
const BOTTOM_PAD = ROW_H

/** "ip:port" → 主机部分;与 types.displayHost 同规则,保证方向判定
 *  与端点标签视觉一致(两侧同串比较,不受端口剥离影响) */
function hostOf(endpoint: string): string {
  const i = endpoint.lastIndexOf(':')
  if (i <= 0) return endpoint
  const tail = endpoint.slice(i + 1)
  // IPv6 端点(多冒号)整体是主机,不剥离;仅 IPv4:port / 裸数字尾段拆分
  if (endpoint.includes(':') && endpoint.split(':').length > 2) return endpoint
  if (/^\d+$/.test(tail) && tail.length <= 5) return endpoint.slice(0, i)
  return endpoint
}

function fmtTime(t: number): string {
  return t.toFixed(3)
}

/**
 * 计算时间流布局。确定性:无随机、无时间依赖、只依赖入参;O(n) 单遍扫描。
 * 报文须已按 time 升序(Conversation.packets 契约保证)。
 */
export function computeFlowLayout(packets: Packet[], opts: FlowLayoutOptions): FlowLayout {
  const clientHost = hostOf(opts.client)
  const serverHost = opts.server ? hostOf(opts.server) : undefined
  const maxRows = opts.maxRows ?? MAX_FLOW_ROWS
  const tickEvery = opts.tickEvery ?? 1

  const total = packets.length
  // 截断保留首尾:首包(握手)与尾包(FIN/RST)是排障关键,步长降采样与
  // SequenceDiagram 同策略;truncated 时才需要尾包保底
  let rows: FlowRow[] = []
  let truncated = false
  if (total <= maxRows) {
    rows = new Array(total)
  } else {
    truncated = true
    rows = new Array(maxRows)
    const stride = Math.ceil(total / maxRows)
    let w = 0
    for (let i = 0; i < total && w < maxRows; i += stride) {
      rows[w++] = makeRow(packets[i], w, clientHost, serverHost)
    }
    // 尾包保底:采样可能错过最后一个报文。两种路径都不得产生重复 packetNumber
    // (同帧两行 → FlowTimeline key 冲突 + 同包画两行):
    // 采样恰好命中尾包(i 递增步长跨到 total-1,total % stride === 1)时
    // rows 里已有尾包,此时不应再追加;rows.some 避免最后两行同号。
    const last = packets[total - 1]
    if (w > 0 && rows[w - 1] !== undefined && (rows[w - 1] as FlowRow).number !== last.number) {
      // 替换行 seq 用 w(而非 w-1):rows[w++] = makeRow(..., w, ...) 里右值 w 是
      // 递增后的值,被替换行原本的 seq 就是 w —— 用 w-1 会让替换行与倒数第二行
      // y 相同(非单调);探针实证恢复 w 后 y 严格单调(对抗审查此条为误报)
      rows[w - 1] = makeRow(last, w, clientHost, serverHost)
    } else if (w < maxRows && !rows.some((r) => r !== undefined && r.number === last.number)) {
      rows[w++] = makeRow(last, w, clientHost, serverHost)
    }
    rows = rows.slice(0, w)
  }

  function makeRow(p: Packet, seq: number, ch: string, sh: string | undefined): FlowRow {
    // 方向判定:request/response 用 Packet.direction;'other' 按 srcIp 与
    // client/server 主机串比较,都判不了 → neutral(中性短横线)
    let dir: FlowDir
    if (p.direction === 'request') dir = 'a2b'
    else if (p.direction === 'response') dir = 'b2a'
    else if (p.srcIp != null && p.srcIp === ch) dir = 'a2b'
    else if (p.srcIp != null && sh != null && p.srcIp === sh) dir = 'b2a'
    else dir = 'neutral'
    const y = FIRST_ROW_TOP + seq * ROW_H
    return {
      number: p.number,
      y,
      dir,
      label: `#${p.number} ${p.info ?? p.proto} · ${p.len}B`,
      time: p.time,
      timeLabel: fmtTime(p.time),
      timeEpoch: p.timeEpoch,
      len: p.len,
      proto: p.proto,
      info: p.info ?? '',
      anomaly: (p.tcpAnalysis?.length ?? 0) > 0,
    }
  }

  if (!truncated) {
    for (let i = 0; i < total; i++) rows[i] = makeRow(packets[i], i, clientHost, serverHost)
  }

  // 时间刻度列:每 tickEvery 行留一个,首行保底(否则顶部无时间锚点)
  const ticks: FlowTick[] = []
  const step = Math.max(1, Math.floor(tickEvery))
  for (let i = 0; i < rows.length; i += step) {
    const r = rows[i]
    ticks.push({ rowIndex: i, timeLabel: r.timeLabel, timeEpoch: r.timeEpoch })
  }

  const height = rows.length > 0 ? rows[rows.length - 1].y + BOTTOM_PAD : FIRST_ROW_TOP + BOTTOM_PAD

  return {
    rows,
    ticks,
    width: 520, // 与 layoutSequence 同宽,导出 PNG 的默认命名/比例保持一致
    height,
    rowHeight: ROW_H,
    headerHeight: FLOW_HEADER_H,
    truncated,
    total,
  }
}
