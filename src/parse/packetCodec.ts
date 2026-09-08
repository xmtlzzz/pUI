import type { Packet } from '../model/types'

/**
 * Worker 传输瘦身编解码(PacketLens 借鉴 #1「即用即弃」传输降维)。
 *
 * 背景:parseWorker 把 Packet[] 直接 postMessage 回主线程时,结构化克隆要逐包
 * 复制 ~45 个自有属性的对象图(10 万包 ≈ 数百万键),克隆耗时与内存都线性放大。
 * 列式(columnar)打包把「每包一个对象」转成「每字段一个数组」,通道上只有
 * ~45 个数组对象,克隆开销从 O(包数×字段数) 的对象复制降为少数大数组的
 * 连续内存复制 —— 与 PacketLens「剥离深层属性、仅传扁平数据」同源,但保留了
 * 完整字段(本工具的分析层全量消费报文字段,不能只传展示所需)。
 *
 * 形状:每字段一列 `{ values: number[]|string[]|boolean[], widths?: number[] }`。
 * - 单值字段:widths 省略,values[i] 即第 i 包的该字段;
 * - 变长字段(tcpSackBlocks/tcpAnalysis/… 的「属性键→值数组」形态,见下):
 *   widths[i] 是第 i 包在该列的取值数,values 是所有包取值的扁平串联。
 *   取值数 0 = 该包此字段 undefined(用「宽度 0」表达稀疏,不编造 null/0)。
 *
 * 字段清单与 Packet 接口一一对应:新增 Packet 字段时必须同步这里与
 * PACKET_NUM_FIELDS/PACKET_CODED_FIELDS(测试用全字段往返钉住)。

 * 纯函数、确定性:同输入同输出;主线程 columnsToPackets 一次性重建 Packet[],
 * 公共 API(Packet[] 形状)零变化。
 */

/** 变长字段的列形态:values 扁平存放所有包的取值,widths[i] = 第 i 包的取值数 */
export interface VarColumn {
  values: Array<number | string | boolean>
  widths: number[]
}

export interface PacketColumns {
  columns: Record<string, number[] | string[] | boolean[] | VarColumn>
}

/**
 * 变长字段编解码表:Packet 上「属性键是字段名、值是数组」的三个字段。
 * tcpSackBlocks 是嵌套数组 [number, number] —— 拍平为「每块两个数字」,
 * 宽度按 2 计;重建时按步长 2 配对。
 */
const VAR_NESTED: Record<'tcpSackBlocks', { readonly step: 2 }> = { tcpSackBlocks: { step: 2 } }

/** 单值数值字段(整数/浮点) */
const NUM_FIELDS = [
  'number',
  'time',
  'timeEpoch',
  'len',
  'capLen',
  'srcPort',
  'dstPort',
  'tcpSeq',
  'tcpAck',
  'tcpStream',
  'tcpWindow',
  'tcpLen',
  'tcpCompleteness',
  'tcpDupAckNum',
  'httpTime',
] as const

/** 单值布尔字段 */
const BOOL_FIELDS = ['smb2Response'] as const

/** 单值字符串字段 */
const STR_FIELDS = [
  'interfaceId',
  'srcIp',
  'dstIp',
  'srcMac',
  'dstMac',
  'tcpFlags',
  'httpMethod',
  'httpUri',
  'httpCode',
  'dnsQuery',
  'tlsType',
  'info',
  'sshProtocol',
  'sshChannelType',
  'rdpNegProtocols',
  'rdpClientName',
  'vncProtoVer',
  'smb2Cmd',
  'smb2Tree',
] as const

/** 枚举字符串字段(transport/direction:受限值域,按字符串传输) */
const ENUM_STR_FIELDS = ['transport', 'proto', 'direction'] as const

/** 变长(字符串数组)字段 */
const VAR_STR_FIELDS = ['tcpAnalysis'] as const

/** FieldValue 读取:Record 直取(字段名即属性键) */
type PacketKey = keyof Packet

function pushVar(col: VarColumn, values: Array<number | string | boolean> | undefined): void {
  if (values == null) {
    col.widths.push(0)
    return
  }
  col.widths.push(values.length)
  for (const v of values) col.values.push(v)
}

/** Packet[] → 列式(Worker 端调用;纯函数,不改入参) */
export function packetColumns(packets: Packet[]): PacketColumns {
  const columns: PacketColumns['columns'] = {}
  const numCols: Record<string, Array<number | undefined>> = {}
  const boolCols: Record<string, Array<boolean | undefined>> = {}
  const strCols: Record<string, Array<string | undefined>> = {}
  const varStrCols: Record<string, VarColumn> = {}
  const sack: VarColumn = { values: [], widths: [] }

  for (const p of packets) {
    for (const f of NUM_FIELDS) numCols[f] = (numCols[f] ?? []).concat(p[f as PacketKey] as number | undefined)
    for (const f of BOOL_FIELDS) boolCols[f] = (boolCols[f] ?? []).concat(p[f as PacketKey] as boolean | undefined)
    const strAll = [...STR_FIELDS, ...ENUM_STR_FIELDS] as const
    for (const f of strAll) strCols[f] = (strCols[f] ?? []).concat(p[f as PacketKey] as string | undefined)
    for (const f of VAR_STR_FIELDS) {
      if (!varStrCols[f]) varStrCols[f] = { values: [], widths: [] }
      pushVar(varStrCols[f], p[f as PacketKey] as string[] | undefined)
    }
    const blocks = p.tcpSackBlocks
    if (blocks == null) {
      sack.widths.push(0)
    } else {
      sack.widths.push(blocks.length * VAR_NESTED.tcpSackBlocks.step)
      for (const [l, r] of blocks) {
        sack.values.push(l, r)
      }
    }
  }

  // undefined 在数组里保留为洞/undefined 项:通道序列化(JSON)会丢弃,
  // 重建侧以 hasOwnProperty/!== undefined 判键 —— 语义与「字段缺失」一致
  for (const [f, col] of Object.entries(numCols)) columns[f] = col as number[]
  for (const [f, col] of Object.entries(boolCols)) columns[f] = col as boolean[]
  for (const [f, col] of Object.entries(strCols)) columns[f] = col as string[]
  for (const [f, col] of Object.entries(varStrCols)) columns[f] = col
  if (packets.length > 0) columns.tcpSackBlocks = sack
  return { columns }
}

/** 从变宽列取第 i 包的取值数组 */
function takeVar(col: VarColumn, i: number): Array<number | string | boolean> {
  // 前缀和按需重算(O(列宽) 每包):重建是单次线性扫描,避免额外累积状态
  let before = 0
  for (let k = 0; k < i; k++) before += col.widths[k]
  const w = col.widths[i]
  return col.values.slice(before, before + w)
}

/** 列式 → Packet[](主线程端调用;纯函数) */
export function columnsToPackets(cols: PacketColumns): Packet[] {
  const columns = cols.columns
  const isVar = (c: unknown): c is VarColumn =>
    c != null && typeof c === 'object' && !Array.isArray(c) && 'widths' in c
  const width = (f: string): number => {
    const c = columns[f]
    if (c == null) return 0
    if (isVar(c)) return c.widths.length
    return (c as unknown[]).length
  }
  const n = Math.max(
    ...NUM_FIELDS.map((f) => width(f)),
    ...BOOL_FIELDS.map((f) => width(f)),
    ...STR_FIELDS.map((f) => width(f)),
    ...ENUM_STR_FIELDS.map((f) => width(f)),
    ...VAR_STR_FIELDS.map((f) => width(f)),
    width('tcpSackBlocks'),
    0,
  )
  const out: Packet[] = []
  for (let i = 0; i < n; i++) {
    const p = {} as Record<string, unknown>
    // null 与 undefined 都视为无值:结构化克隆保留 undefined,而 JSON 通道(更苛刻的
    // 模拟)会把列内的 undefined 变 null —— 两种通道语义在「字段缺失」上必须收敛一致
    const put = (f: string, v: unknown): void => {
      if (v !== undefined && v !== null) p[f] = v
    }
    for (const f of NUM_FIELDS) put(f, (columns[f] as Array<number | undefined> | undefined)?.[i])
    for (const f of BOOL_FIELDS) put(f, (columns[f] as Array<boolean | undefined> | undefined)?.[i])
    const strAll = [...STR_FIELDS, ...ENUM_STR_FIELDS] as const
    for (const f of strAll) put(f, (columns[f] as Array<string | undefined> | undefined)?.[i])
    for (const f of VAR_STR_FIELDS) {
      const col = columns[f] as VarColumn | undefined
      if (col) {
        const vals = takeVar(col, i).map((x) => String(x))
        put(f, vals.length ? vals : undefined)
      }
    }
    const sack = columns.tcpSackBlocks as VarColumn | undefined
    if (sack) {
      const flat = takeVar(sack, i).map((x) => Number(x))
      const blocks: Array<[number, number]> = []
      for (let k = 0; k + 1 < flat.length; k += 2) blocks.push([flat[k], flat[k + 1]])
      put('tcpSackBlocks', blocks.length ? blocks : undefined)
    }
    out.push(p as unknown as Packet)
  }
  return out
}
