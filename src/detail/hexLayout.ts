/**
 * hex 文本的字节级布局解析(Wireshark 式 hex dump 联动基础层)。
 *
 * hex 文本形态(tshark -x / Wireshark 复制为 hex dump):
 *   行 = 4-5 位十六进制偏移 + 空格 + 16 个单空格分隔的十六进制字节 + 双空格 + ASCII
 *   例:0000  00 aa bb cc dd ee 00 11 22 33 44 55 08 00 45 00   ........"3DU..E.
 *   末行可为不完整行(截断帧):字节数 < 16。
 *
 * 数据层限制:抓包 JSON 是 -e 平铺精选字段(见 src-tauri CAPTURE_FIELDS),
 * 不含帧内字段的字节偏移(_raw/offset 字段)。因此 hex 文本自身的行列布局
 * 是唯一可精确计算的字节定位依据 —— 联动时字段侧用「协议层估算区域」
 * (见 packetTree 的 detailRegion),此处只负责「字节偏移 ↔ hex 文本行列」。
 */

export interface HexLayoutLine {
  /** 该行起始字节偏移(十六进制 offset 列解析) */
  offset: number
  /** 该行实际字节数(末行可 < 16) */
  byteCount: number
  /** 每个字节双字符的起始列位置(相对整行文本) */
  bytePos: number[]
  text: string
}

/** 解析 hex 文本为逐行布局;非数据行(空行/尾注)跳过 */
export function parseHexLayout(hexText: string): HexLayoutLine[] {
  const lines: HexLayoutLine[] = []
  for (const text of hexText.split('\n')) {
    // 锚定行首:offset(4-5 位 hex)+ 空白 + 单空格分隔的字节对
    // 字节对用「单空格」分隔(与 ASCII 前的双空格区分,避免吞进 ASCII 列)
    const m = /^([0-9a-fA-F]{4,5})\s+([0-9a-fA-F]{2}(?: [0-9a-fA-F]{2})*)/.exec(text)
    if (!m) continue
    const offset = Number.parseInt(m[1], 16)
    const byteStart = m[0].length - m[2].length // 第一个字节双字符的起始列
    const bytePos: number[] = []
    for (let i = 0; i < m[2].length; i += 3) bytePos.push(byteStart + i)
    lines.push({ offset, byteCount: bytePos.length, bytePos, text })
  }
  return lines
}

export interface HexBytePos {
  /** 命中行下标(parseHexLayout 输出中的行序) */
  line: number
  /** 行内字节下标(0..byteCount-1) */
  byteIndex: number
}

/** 字节偏移 → [行, 行内字节下标];越界/负偏移返回 null */
export function locateByte(hexText: string, byteOffset: number): HexBytePos | null {
  if (byteOffset < 0) return null
  const lines = parseHexLayout(hexText)
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]
    if (byteOffset >= l.offset && byteOffset < l.offset + l.byteCount) {
      return { line: i, byteIndex: byteOffset - l.offset }
    }
  }
  return null
}

export interface LineRange {
  line: number
  /** 行内起始字节下标(含) */
  from: number
  /** 行内结束字节下标(不含,1..16) */
  to: number
}

/** 字节范围 [fromOffset, toOffset) → 逐行高亮区间(跨行拆成多段);空/越界返回空数组 */
export function rangeToLines(hexText: string, fromOffset: number, toOffset: number): LineRange[] {
  if (toOffset <= fromOffset) return []
  const out: LineRange[] = []
  const layout = parseHexLayout(hexText)
  for (let i = 0; i < layout.length; i++) {
    const l = layout[i]
    const start = Math.max(fromOffset, l.offset)
    const end = Math.min(toOffset, l.offset + l.byteCount)
    if (end > start) out.push({ line: i, from: start - l.offset, to: end - l.offset })
  }
  return out
}
