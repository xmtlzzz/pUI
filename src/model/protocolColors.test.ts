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
    expect(c1).toBe(c2) // 稳定(同名同色)
    expect(c1).not.toBe('#64748b') // 未知协议不再灰色
    // 注:PALETTE 仅 20 色,哈希取模必然碰撞;承诺的是「稳定」而非「互不相同」
    expect(protocolColor('unknownproto').length).toBeGreaterThanOrEqual(4)
  })

  it('provides a light badge background for unknown protocols', () => {
    const st = protocolStyle('someexotic')
    expect(st.fg).toMatch(/^#/)
    expect(st.bg).toMatch(/^rgb/)
  })
})
