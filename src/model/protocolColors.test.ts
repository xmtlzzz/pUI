import { describe, expect, it } from 'vitest'
import { protocolColor, protocolStyle } from './protocolColors'

describe('protocolColors', () => {
  it('colors common protocols distinctly', () => {
    const colors = ['tcp', 'http', 'dns', 'ssh', 'tls'].map(protocolColor)
    expect(new Set(colors).size).toBeGreaterThanOrEqual(4)
  })

  it('assigns stable non-gray colors to unknown protocols', () => {
    const c1 = protocolColor('unknownproto')
    const c2 = protocolColor('unknownproto')
    const c3 = protocolColor('anotherproto')
    expect(c1).toBe(c2) // 稳定
    expect(c1).not.toBe('#64748b')
    expect(c1).not.toBe(c3) // 不同协议不同色
  })

  it('provides a light badge background for unknown protocols', () => {
    const st = protocolStyle('someexotic')
    expect(st.fg).toMatch(/^#/)
    expect(st.bg).toMatch(/^rgb/)
  })
})
