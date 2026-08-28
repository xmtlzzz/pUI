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
 *  onProgress 每块回调一次(帧数进度)。Tauri 缺席时回落浏览器 fixture 路径。 */
export async function openCapture(
  path: string,
  onProgress?: (frames: number) => void,
): Promise<{ meta: CaptureMeta; packets: Packet[]; path: string }> {
  if (isTauri()) {
    const packets: Packet[] = []
    const state = { count: 0 }
    const channel = new Channel<CaptureChunkMsg>()
    channel.onmessage = (msg) => {
      parsePacketsBatch(state, msg.text, packets)
      onProgress?.(state.count)
    }
    const out = await invoke<CaptureStreamedResult>('open_capture', { path, onChunk: channel })
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
    const packets: Packet[] = []
    const state = { count: 0 }
    const channel = new Channel<CaptureChunkMsg>()
    channel.onmessage = (msg) => {
      parsePacketsBatch(state, msg.text, packets)
      onProgress?.(state.count)
    }
    const out = await invoke<CaptureStreamedResult>('open_capture_data', { fileName: `${name}.pcapng`, base64Data: base64, onChunk: channel })
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

export async function saveText(defaultName: string, content: string): Promise<string | null> {
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
  return invoke<string | null>('save_text', { defaultName, content })
}

export async function getTsharkVersion(): Promise<string | null> {
  if (!isTauri()) return null
  try {
    return await invoke<string | null>('tshark_version')
  } catch {
    return null
  }
}
