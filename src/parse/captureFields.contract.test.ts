import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CAPTURE_FIELDS } from './captureFields'

/**
 * 字段清单是三处同步的契约(plan M0):
 *   - src/parse/captureFields.ts   前端源
 *   - src-tauri/src/tshark.rs      Rust 权威实现(实际拼 tshark 命令行)
 *   - scripts/gen-parsed.mjs       fixture 生成(正则抓取前端源)
 * 任一处漂移都会让「解析器以为有某字段、抓包却没取」这类问题在运行时才暴露,
 * 因此这里用测试把三处钉在一起。
 */
describe('capture field contract', () => {
  const root = join(__dirname, '..', '..')

  it('Rust CAPTURE_FIELDS 与 TS 清单逐字一致且同序', () => {
    const rs = readFileSync(join(root, 'src-tauri', 'src', 'tshark.rs'), 'utf-8')
    // 取 `pub const CAPTURE_FIELDS: &[&str] = &[ ... ];` 块内的字符串字面量
    const block = rs.match(/pub const CAPTURE_FIELDS: &\[&str\] = &\[([\s\S]*?)\];/)
    expect(block, 'tshark.rs 中未找到 CAPTURE_FIELDS 定义').not.toBeNull()
    const rustFields = [...block![1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
    expect(rustFields).toEqual(CAPTURE_FIELDS)
  })

  it('gen-parsed.mjs 的提取正则能抓到清单里的每个字段', () => {
    // gen-parsed.mjs 用正则从 captureFields.ts 抓字段名;新增含数字/下划线的字段时
    // 若正则字符集不覆盖,fixture 会静默少字段(生成时不报错、解析时才发现)
    const genSrc = readFileSync(join(root, 'scripts', 'gen-parsed.mjs'), 'utf-8')
    const reSrc = genSrc.match(/matchAll\((\/[^/]+\/[a-z]*)\)/)
    expect(reSrc, 'gen-parsed.mjs 中未找到字段提取正则').not.toBeNull()

    const fieldsSrc = readFileSync(join(root, 'src', 'parse', 'captureFields.ts'), 'utf-8')
    // 用与 gen-parsed.mjs 完全相同的正则复算一遍,结果必须等于导出的清单
    const body = reSrc![1].replace(/^\//, '').replace(/\/[a-z]*$/, '')
    const flags = reSrc![1].match(/\/([a-z]*)$/)?.[1] ?? ''
    const re = new RegExp(body, flags.includes('g') ? flags : flags + 'g')
    const scraped = [...fieldsSrc.matchAll(re)].map((m) => m[1])
    expect(scraped).toEqual(CAPTURE_FIELDS)
  })

  it('gen-parsed.mjs 的字段数下限断言不会被新清单误触发', () => {
    const genSrc = readFileSync(join(root, 'scripts', 'gen-parsed.mjs'), 'utf-8')
    const min = genSrc.match(/FIELDS\.length < (\d+)/)
    expect(min).not.toBeNull()
    expect(CAPTURE_FIELDS.length).toBeGreaterThanOrEqual(Number(min![1]))
  })

  it('清单无重复项', () => {
    expect(new Set(CAPTURE_FIELDS).size).toBe(CAPTURE_FIELDS.length)
  })

  it('包含 M0 分析引擎所需的新增事实字段', () => {
    // 每个字段的用途见 captureFields.ts 注释;缺任一项会让对应分析能力静默降级
    for (const f of [
      'tcp.stream', // 流身份:端口复用/并发连接不能靠端点对区分
      'tcp.len', // TCP 载荷长度:序列号推进必须用它,不能用 frame.len
      'tcp.options.sack_le', // SACK 左边界(平铺模式下为并行数组)
      'tcp.options.sack_re', // SACK 右边界
      'tcp.analysis.duplicate_ack_num', // 第几个重复 ACK
      'tcp.analysis.spurious_retransmission', // 伪重传:区分"重传≠数据丢失"
      'frame.cap_len', // 捕获长度:截断/采集完整性信号
      'tcp.completeness', // 握手完整性位掩码:mid-stream 判定
    ]) {
      expect(CAPTURE_FIELDS, `缺少字段 ${f}`).toContain(f)
    }
  })

  it('不含已明确后置到 M5 的字段(避免无谓放大 JSON 体积)', () => {
    // 窗口/完整 RTT/zero-window 等属 M5 增强,M0 不引入
    for (const f of ['tcp.window_size', 'tcp.window_size_value', 'tcp.analysis.zero_window', 'tcp.analysis.window_full']) {
      expect(CAPTURE_FIELDS, `${f} 属 M5,不应在 M0 引入`).not.toContain(f)
    }
  })
})
