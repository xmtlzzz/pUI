/**
 * TCP 32 位序列号算术(RFC 1982 serial number arithmetic)。
 *
 * 序列号空间是 2^32 的环:4294967295 的下一个是 0。因此不能用普通数值比较判定先后,
 * 否则回绕处会把"新数据"判成"旧数据",进而在序列空间里凭空造出巨大的 Gap。
 * 判定改为看有符号差值落在环的哪半边。
 *
 * 已知局限(RFC 1982 固有):相距 ≥ 2^31 的两个序列号无法定序。真实 TCP 流不会出现
 * 这种跨度(需要一次跳过 2GB 未确认数据),但畸形/拼接抓包可能触发,
 * 此处保证给出确定且可复现的结果,而不是随机或异常。
 */

/** 序列号空间大小 2^32 */
export const SEQ_SPACE = 0x1_0000_0000

/** 半空间 2^31:超过该距离即无法定序 */
const HALF = 0x8000_0000

/** 归一化到 [0, 2^32):解析层理论上不会越界,但畸形抓包可能给出脏值,
 *  先归一再运算,避免脏数据传播成错误的 Gap */
function norm(x: number): number {
  // >>> 0 会把非整数截断并映射到 32 位无符号,负数与超界值都能正确回卷
  return x >>> 0
}

/**
 * 序列号比较:返回负/零/正,语义同 Array#sort 的 comparator。
 *
 * 距离恰为 2^31 时无法定序,此处固定返回负值(视 a 在前),
 * 保证同一输入永远得到同一结果,分析输出可复现。
 */
export function seqCmp(a: number, b: number): number {
  const d = (norm(a) - norm(b)) | 0 // 有符号 32 位环绕差
  if (d === 0) return 0
  // d 已是有符号 32 位:正表示 a 在 b 之后,负表示之前;
  // 恰好 -2^31(不可定序)自然落入负分支,行为确定
  return d
}

export function seqLt(a: number, b: number): boolean {
  return seqCmp(a, b) < 0
}

export function seqGt(a: number, b: number): boolean {
  return seqCmp(a, b) > 0
}

export function seqLte(a: number, b: number): boolean {
  return seqCmp(a, b) <= 0
}

export function seqGte(a: number, b: number): boolean {
  return seqCmp(a, b) >= 0
}

/** 序列号加法,在 2^32 处回绕 */
export function seqAdd(seq: number, delta: number): number {
  return norm(norm(seq) + delta)
}

/**
 * 有符号距离 a - b(字节数),跨回绕仍正确。
 * 正值表示 a 在 b 之后。距离超过半空间时结果按环的近侧解释。
 */
export function seqDiff(a: number, b: number): number {
  return (norm(a) - norm(b)) | 0
}

/** 距离是否超出可定序范围(仅用于诊断/降级,不用于常规比较) */
export function seqAmbiguous(a: number, b: number): boolean {
  return Math.abs(seqDiff(a, b)) === HALF
}
