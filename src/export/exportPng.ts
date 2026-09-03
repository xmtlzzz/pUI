import { hostOf } from '../model/types'

/** 导出画布高度上限:超大会议导出会先分配巨型 canvas 直接 OOM
 * (520×(72+30n)px,2 万包 >1GB RGBA),超过上限拒绝导出并提示先筛选。 */
export const MAX_EXPORT_HEIGHT = 20000

export function exportHeightWithinLimit(h: number): boolean {
  return h <= MAX_EXPORT_HEIGHT
}

/** Windows 文件名非法字符(含 IPv6 冒号)替换为连字符 */
const WIN_ILLEGAL = /[<>:"/\\|?*\x00-\x1f]/g
function safePart(s: string): string {
  return hostOf(s).replace(WIN_ILLEGAL, '-').replace(/-{2,}/g, '-')
}

export function defaultPngName(client: string, server: string, proto: string): string {
  return `${safePart(client)}-${safePart(server)}-${proto.replace(WIN_ILLEGAL, '-')}.png`
}

/** 导出时克隆 SVG 并去掉缩放 transform,避免把 scale(zoom) 烤进图片导致裁剪/留白 */
export function serializeSvgForExport(svgEl: SVGSVGElement): string {
  const clone = svgEl.cloneNode(true) as SVGSVGElement
  clone.style.transform = ''
  clone.style.transformOrigin = ''
  return new XMLSerializer().serializeToString(clone)
}

export async function exportSvgPng(svgEl: SVGSVGElement | null, fileName: string): Promise<void> {
  if (!svgEl) {
    // 不再静默返回:上层用户以为导出了实际没保存 —— 抛出让调用方 try/catch 提示
    throw new Error('图表尚未渲染完成')
  }
  const blob = await svgToBlob(svgEl)
  const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core')
    const base64 = await blobToBase64(blob)
    await invoke('save_png', { defaultName: fileName, base64Data: base64 })
  } else {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fileName
    a.click()
    URL.revokeObjectURL(url)
  }
}

function svgToBlob(svgEl: SVGSVGElement): Promise<Blob> {
  const xml = serializeSvgForExport(svgEl)
  const svg64 = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(xml)
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => {
      const canvas = document.createElement('canvas')
      const w = svgEl.viewBox.baseVal.width || svgEl.width.baseVal.value
      const h = svgEl.viewBox.baseVal.height || svgEl.height.baseVal.value
      if (!exportHeightWithinLimit(h)) {
        return reject(new Error(`会话过大(时序图高度 ${Math.round(h)}px 超出导出上限),请先筛选后再导出`))
      }
      canvas.width = w
      canvas.height = h
      const ctx = canvas.getContext('2d')
      if (!ctx) return reject(new Error('no 2d context'))
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, w, h)
      ctx.drawImage(img, 0, 0)
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('toBlob failed'))), 'image/png')
    }
    img.onerror = () => reject(new Error('svg load failed'))
    img.src = svg64
  })
}

async function blobToBase64(blob: Blob): Promise<string> {
  const buf = new Uint8Array(await blob.arrayBuffer())
  let bin = ''
  for (const b of buf) bin += String.fromCharCode(b)
  return btoa(bin)
}
