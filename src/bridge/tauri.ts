import { invoke } from '@tauri-apps/api/core'
import { parsePackets } from '../parse/parsePackets'
import type { CaptureMeta, Packet } from '../model/types'

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function computeMeta(fileName: string, packets: Packet[], fileSize = 0): CaptureMeta {
  let timeStart = Number.POSITIVE_INFINITY
  let timeEnd = Number.NEGATIVE_INFINITY
  for (const p of packets) {
    if (p.time < timeStart) timeStart = p.time
    if (p.time > timeEnd) timeEnd = p.time
  }
  return {
    fileName,
    packetCount: packets.length,
    interfaces: 1,
    timeStart: packets.length ? timeStart : 0,
    timeEnd: packets.length ? timeEnd : 0,
    fileSize,
  }
}

export async function openCapture(path: string): Promise<{ meta: CaptureMeta; packets: Packet[]; path: string }> {
  if (isTauri()) {
    const out = await invoke<{ json: string; size: number; path: string }>('open_capture', { path })
    const packets = parsePackets(out.json)
    return { meta: computeMeta(path.split(/[\\/]/).pop() ?? path, packets, out.size), packets, path: out.path }
  }
  // browser dev fallback: 读取已提交的解析产物
  const name = path.split(/[\\/]/).pop()?.replace(/\.(pcap|pcapng|gz)$/i, '') ?? 'http'
  const res = await fetch(`/fixtures/parsed/${name}.json`)
  if (!res.ok) throw new Error(`no fixture for ${name}`)
  const raw = await res.text()
  const packets = parsePackets(raw)
  return { meta: computeMeta(`${name}.pcapng`, packets), packets, path }
}

export async function openSample(name: string): Promise<{ meta: CaptureMeta; packets: Packet[]; path: string }> {
  const url = `/fixtures/examples/${name}.pcapng`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`missing example: ${name}`)
  if (isTauri()) {
    const buf = new Uint8Array(await res.arrayBuffer())
    let bin = ''
    for (const b of buf) bin += String.fromCharCode(b)
    const base64 = btoa(bin)
    const out = await invoke<{ json: string; size: number; path: string }>('open_capture_data', { fileName: `${name}.pcapng`, base64Data: base64 })
    const packets = parsePackets(out.json)
    return { meta: computeMeta(`${name}.pcapng`, packets, out.size), packets, path: out.path }
  }
  const jres = await fetch(`/fixtures/examples/parsed/${name}.json`)
  const raw = await jres.text()
  const packets = parsePackets(raw)
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
