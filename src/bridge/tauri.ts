import { invoke } from '@tauri-apps/api/core'
import { Channel } from '@tauri-apps/api/core'
import { parsePacketsAsync, parsePacketsBatch } from '../parse/parseAsync'
import type { CaptureMeta, Packet } from '../model/types'

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function computeMeta(fileName: string, packets: Packet[], fileSize = 0, parseMs = 0): CaptureMeta {
  let timeStart = Number.POSITIVE_INFINITY
  let timeEnd = Number.NEGATIVE_INFINITY
  // 接口数:按 frame.interface_id 去重;缺失(旧版 tshark/纯 IP)时回落 1
  const interfaces = new Set<string>()
  for (const p of packets) {
    if (p.time < timeStart) timeStart = p.time
    if (p.time > timeEnd) timeEnd = p.time
    if (p.interfaceId != null) interfaces.add(p.interfaceId)
  }
  return {
    fileName,
    packetCount: packets.length,
    interfaces: interfaces.size || 1,
    timeStart: packets.length ? timeStart : 0,
    timeEnd: packets.length ? timeEnd : 0,
    fileSize,
    parseMs,
  }
}

interface CaptureChunkMsg {
  seq: number
  text: string
  done: boolean
}

interface CaptureStreamedResult {
  size: number
  path: string
  frames: number
}

/** 打开抓包(流式):Rust 按帧边界分块经 Channel 回传,前端逐块解析追加,
 *  onProgress 每块回调一次(帧数进度)。Tauri 缺席时回落浏览器 fixture 路径。
 *  数据完整性红线:分块解析出错绝不能静默 —— onmessage 里没有 await 链,
 *  错误必须记下并在 invoke 返回后抛出;帧数对不上同样视为损坏。
 *  command 与 invokeArgs 必须成对传入(open_capture→path / open_capture_data→
 *  fileName+base64Data):曾因命令名写死,示例参数被发往 open_capture 报
 *  「missing required key path」。 */
async function receiveStreamedCapture(
  command: 'open_capture' | 'open_capture_data',
  invokeArgs: Record<string, unknown>,
  onProgress?: (frames: number) => void,
): Promise<{ packets: Packet[]; out: CaptureStreamedResult }> {
  const packets: Packet[] = []
  const state = { count: 0 }
  let parseError: Error | null = null
  const channel = new Channel<CaptureChunkMsg>()
  channel.onmessage = (msg) => {
    try {
      parsePacketsBatch(state, msg.text, packets)
    } catch (e) {
      // 首个错误生效;后续块跳过解析但继续消费(保持消息序,防状态错乱)
      parseError = parseError ?? (e instanceof Error ? e : new Error(String(e)))
    }
    onProgress?.(state.count)
  }
  const out = await invoke<CaptureStreamedResult>(command, { ...invokeArgs, onChunk: channel })
  if (parseError) throw parseError
  if (out.frames > 0 && packets.length === 0) {
    throw new Error(`分块解析未产出任何报文(Rust 报告 ${out.frames} 帧):批格式契约不匹配`)
  }
  if (packets.length > 0 && out.frames > 0 && Math.abs(packets.length - out.frames) > out.frames * 0.5 + 8) {
    // 帧数严重偏差(>50%+8)视为传输/解析损坏;小偏差容忍(畸形帧被跳过)
    throw new Error(`分块解析帧数不符(前端 ${packets.length} / Rust ${out.frames}):数据可能不完整`)
  }
  return { packets, out }
}

export async function openCapture(
  path: string,
  onProgress?: (frames: number) => void,
): Promise<{ meta: CaptureMeta; packets: Packet[]; path: string }> {
  if (isTauri()) {
    const { packets, out } = await receiveStreamedCapture('open_capture', { path }, onProgress)
    return { meta: computeMeta(path.split(/[\\/]/).pop() ?? path, packets, out.size), packets, path: out.path }
  }
  // browser dev fallback: 读取已提交的解析产物
  const name = path.split(/[\\/]/).pop()?.replace(/\.(pcap|pcapng|gz)$/i, '') ?? 'http'
  const res = await fetch(`/fixtures/parsed/${name}.json`)
  if (!res.ok) throw new Error(`no fixture for ${name}`)
  const raw = await res.text()
  const packets = await parsePacketsAsync(raw)
  return { meta: computeMeta(`${name}.pcapng`, packets), packets, path }
}

export async function openSample(
  name: string,
  onProgress?: (frames: number) => void,
): Promise<{ meta: CaptureMeta; packets: Packet[]; path: string }> {
  const url = `/fixtures/examples/${name}.pcapng`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`missing example: ${name}`)
  if (isTauri()) {
    const buf = new Uint8Array(await res.arrayBuffer())
    let bin = ''
    for (const b of buf) bin += String.fromCharCode(b)
    const base64 = btoa(bin)
    const { packets, out } = await receiveStreamedCapture(
      'open_capture_data',
      { fileName: `${name}.pcapng`, base64Data: base64 },
      onProgress,
    )
    return { meta: computeMeta(`${name}.pcapng`, packets, out.size), packets, path: out.path }
  }
  const jres = await fetch(`/fixtures/examples/parsed/${name}.json`)
  if (!jres.ok) throw new Error(`missing example: ${name}`)
  const raw = await jres.text()
  const packets = await parsePacketsAsync(raw)
  return { meta: computeMeta(`${name}.pcapng`, packets), packets, path: name }
}

export async function fetchHex(path: string, frameNumber: number): Promise<string> {
  if (isTauri()) {
    return invoke<string>('fetch_hex', { path, frameNumber })
  }
  const name = path.split(/[\\/]/).pop()?.replace(/\.(pcap|pcapng|gz)$/i, '') ?? 'http'
  const res = await fetch(`/fixtures/parsed/${name}.hex.txt`)
  if (!res.ok) throw new Error(`no hex fixture for ${name}`)
  return res.text()
}

export async function locateTshark(): Promise<string | null> {
  if (!isTauri()) return null
  try {
    return await invoke<string | null>('locate_tshark')
  } catch {
    return null
  }
}

/** 设置 tshark 可执行文件路径(Rust 侧 validate_tshark_path 强校验:绝对路径/exe/文件名含 tshark/非符号链接)。
 *  校验失败会 reject,由调用方展示错误。非 Tauri 环境(浏览器 dev)无 Rust 命令,直接返回。 */
export async function setTsharkPath(path: string): Promise<void> {
  if (!isTauri()) return
  await invoke('set_tshark_path', { path })
}

export async function saveText(
  defaultName: string,
  content: string,
  // 保存对话框过滤器(名称+扩展名):md/html 等文本报告共用 save_text;缺省 Markdown
  filter?: { name: string; extensions: string[] },
): Promise<string | null> {
  if (!isTauri()) {
    // 浏览器回退:直接触发下载
    const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown' }))
    const a = document.createElement('a')
    a.href = url
    a.download = defaultName
    a.click()
    URL.revokeObjectURL(url)
    return defaultName
  }
  return invoke<string | null>('save_text', {
    defaultName,
    content,
    filterName: filter?.name ?? null,
    extensions: filter?.extensions ?? null,
  })
}

/** 二进制导出(Word/.docx 等):字节 base64 后交 Rust save_bytes,经原生保存对话框落盘。
 *  过滤器名称与扩展名由调用方给定(导出报告选格式共用本命令)。
 *  浏览器回退:Blob 直接触发下载。 */
export async function saveBinary(
  defaultName: string,
  data: Uint8Array,
  filterName: string,
  extensions: string[],
): Promise<string | null> {
  if (!isTauri()) {
    const url = URL.createObjectURL(new Blob([data as BlobPart]))
    const a = document.createElement('a')
    a.href = url
    a.download = defaultName
    a.click()
    URL.revokeObjectURL(url)
    return defaultName
  }
  let bin = ''
  for (const b of data) bin += String.fromCharCode(b)
  return invoke<string | null>('save_bytes', {
    defaultName,
    base64Data: btoa(bin),
    filterName,
    extensions,
  })
}

export async function getTsharkVersion(): Promise<string | null> {
  if (!isTauri()) return null
  try {
    return await invoke<string | null>('tshark_version')
  } catch {
    return null
  }
}
