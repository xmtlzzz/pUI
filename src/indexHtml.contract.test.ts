import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from "node:path"

/**
 * index.html 契约(启动链路完整性):三类脚本缺一不可 ——
 * 缺 React 入口 = Vite 不打包应用 = 启动屏永远不退场(实测事故:emotion-ball
 * 重写 index.html 时丢掉 module 入口,release 包卡在"正在启动…");
 * 缺引擎脚本 = 启动屏无表情球;缺 boot 层 = 白屏回归。
 */
const html = readFileSync(resolve(__dirname, '../index.html'), 'utf8')

describe('index.html 启动链路契约', () => {
  it('包含 React 模块入口(Vite 打包的必要条件)', () => {
    expect(html).toContain('<script type="module" src="/src/main.tsx"></script>')
  })

  it('包含 emotion-ball 引擎四件套与接入层(按官方顺序)', () => {
    const order = ['rings.js', 'emotions.js', 'ball.js', 'engine.js', 'boot.js'].map(
      (f) => html.indexOf(`/emotion-ball/js/${f}"`) !== -1 || html.indexOf(`/emotion-ball/${f}"`) !== -1,
    )
    expect(order.every(Boolean)).toBe(true)
    // 官方加载顺序:rings -> emotions -> ball -> engine
    const pos = (s: string) => html.indexOf(s)
    expect(pos('rings.js')).toBeLessThan(pos('emotions.js'))
    expect(pos('emotions.js')).toBeLessThan(pos('ball.js'))
    expect(pos('ball.js')).toBeLessThan(pos('engine.js'))
  })

  it('包含启动层与挂载点', () => {
    expect(html).toContain('id="boot"')
    expect(html).toContain('id="boot-ball"')
    expect(html).toContain('id="root"')
  })
})
