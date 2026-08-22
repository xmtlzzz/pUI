// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { defaultPngName, serializeSvgForExport, exportHeightWithinLimit, MAX_EXPORT_HEIGHT } from './exportPng'

describe('defaultPngName', () => {
  it('builds a readable filename', () => {
    expect(defaultPngName('192.168.1.10:54321', '93.184.216.34:80', 'http')).toBe('192.168.1.10-93.184.216.34-http.png')
  })

  it('strips ports from endpoints', () => {
    expect(defaultPngName('192.168.1.10:54321', '8.8.8.8:53', 'dns')).toBe('192.168.1.10-8.8.8.8-dns.png')
  })

  it('sanitizes Windows-illegal chars from ipv6 hosts', () => {
    expect(defaultPngName('2001:db8::1:443', 'fe80::1:10', 'tls')).toBe('2001-db8-1-fe80-1-tls.png')
  })
})

describe('exportHeightWithinLimit', () => {
  it('拒绝超大高度导出(防巨型 canvas OOM)', () => {
    expect(exportHeightWithinLimit(MAX_EXPORT_HEIGHT)).toBe(true)
    expect(exportHeightWithinLimit(MAX_EXPORT_HEIGHT + 1)).toBe(false)
  })
})

describe('serializeSvgForExport', () => {
  it('strips the zoom transform from the serialized svg', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('viewBox', '0 0 100 50')
    svg.style.transform = 'scale(1.5)'
    svg.style.transformOrigin = 'top left'
    const xml = serializeSvgForExport(svg)
    expect(xml).toContain('viewBox="0 0 100 50"')
    expect(xml).not.toContain('scale(')
    expect(xml).not.toContain('transform')
  })
})
