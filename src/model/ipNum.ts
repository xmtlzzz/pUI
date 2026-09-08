/**
 * IPv4 ↔ 32 位无符号整数互转与数值序比较(PacketLens 借鉴项 #2)。
 *
 * 背景:字符串词法序在跨网段时是错的('192.168.1.3' < '10.0.0.2' 词法为真,
 * 网络序为假;'10.0.0.10' 与 '10.0.0.2' 同理)。筛选候选列表与会话列头排序
 * 需要真正的网络序;IPv4 预转为数字后比较也是热路径(大列表排序)的提速手法。
 *
 * 仅处理点分四段 IPv4;MAC/IPv6/主机名等非 IPv4 形态不在此模块编造数值,
 * 由 compareHosts 回落到既有 localeCompare(numeric) 行为——
 * 字段形态缺失/未知不编造,与「不过度归因」红线同源。
 */

const IP4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** 是否为合法点分四段 IPv4(无前导零:与 tshark ip.src/ip.dst 输出口径一致) */
export function isIp4(s: string): boolean {
  return IP4_RE.test(s)
}

/** IPv4 → 32 位无符号整数;非法形态返回 null(不编造数值) */
export function ip4ToNum(s: string): number | null {
  if (!isIp4(s)) return null
  const [a, b, c, d] = s.split('.')
  return ((Number(a) << 24) | (Number(b) << 16) | (Number(c) << 8) | Number(d)) >>> 0
}

/** 32 位无符号整数 → IPv4;仅接受 [0, 0xFFFFFFFF](与 ip4ToNum 往返闭合) */
export function numToIp4(n: number): string {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`numToIp4: ${n} 超出 32 位无符号整数范围`)
  }
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.')
}

/**
 * 主机标识比较(网络序):双侧均为 IPv4 时按 32 位整数比较;
 * IPv4 与非 IPv4 混排时 IPv4 排在前(确定性分桶:数值地址优先于符号地址);
 * 其余回落 localeCompare(numeric)。
 * 返回值语义与 Array.prototype.sort 的比较器一致(负/零/正)。
 */
export function compareHosts(a: string, b: string): number {
  const na = ip4ToNum(a)
  const nb = ip4ToNum(b)
  if (na != null && nb != null) return na - nb
  if (na != null) return -1
  if (nb != null) return 1
  return a.localeCompare(b, undefined, { numeric: true })
}

/** IP 候选列表排序:IPv4 数值序在前,非 IPv4(MAC/IPv6/主机名)在后按 locale 序。纯函数,不改入参。 */
export function withIp4Sort(hosts: string[]): string[] {
  return [...hosts].sort(compareHosts)
}
