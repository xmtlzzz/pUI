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

  it('gen-parsed.mjs 的提取正则能抓到清单里的每个字段(集合相等,不多不少)', () => {
    // gen-parsed.mjs 用正则从 captureFields.ts 抓字段名,生成 fixture 的 -e 参数。
    // 字符集必须含大写字母:M6 第二批的 rdp.negReq.requestedProtocols 是 Wireshark
    // 官方注册名(camelCase,勿改),曾因正则只认小写被静默漏抓 —— 这里按集合相等
    // 全量比对:清单每个字段都必须被抓到,正则也不许多抓(若注释里出现会被误抓的
    // 引号片段,这里会响,提醒改注释或收紧正则)。
    const genSrc = readFileSync(join(root, 'scripts', 'gen-parsed.mjs'), 'utf-8')
    const reSrc = genSrc.match(/matchAll\((\/[^/]+\/[a-z]*)\)/)
    expect(reSrc, 'gen-parsed.mjs 中未找到字段提取正则').not.toBeNull()

    const fieldsSrc = readFileSync(join(root, 'src', 'parse', 'captureFields.ts'), 'utf-8')
    // 用与 gen-parsed.mjs 完全相同的正则复算一遍
    const body = reSrc![1].replace(/^\//, '').replace(/\/[a-z]*$/, '')
    const flags = reSrc![1].match(/\/([a-z]*)$/)?.[1] ?? ''
    const re = new RegExp(body, flags.includes('g') ? flags : flags + 'g')
    const scraped = [...fieldsSrc.matchAll(re)].map((m) => m[1])
    expect(new Set(scraped)).toEqual(new Set(CAPTURE_FIELDS))
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

  it('包含 M5 窗口事件所需字段(窗口字段已随 M5 事件引擎引入)', () => {
    // tcp.window_size 是零窗口/窗口耗尽检测的前提(M5);缺失时不做推测
    for (const f of ['tcp.window_size']) {
      expect(CAPTURE_FIELDS, `缺少字段 ${f}`).toContain(f)
    }
  })

  it('包含 M6 第二批应用层分析所需字段(SSH/RDP/VNC/SMB 明文观察)', () => {
    // 每个字段的用途见 captureFields.ts 注释;缺任一项会让对应分析能力静默降级
    for (const f of [
      'ssh.protocol', // 版本横幅:密钥交换后全程加密,横幅是唯一明文能力信号
      'ssh.connection_type_name', // 通道类型名:通道打开请求为明文
      'rdp.negReq.requestedProtocols', // 连接协商请求协议位掩码(0x1=SSL 0x2=CredSSP 0x8=RDSTLS)
      'rdp.client.name', // 客户端机器名(仅明文 X.224 cookie 场景落值)
      'vnc.server_proto_ver', // RFB 版本横幅(实机验证仅服务端横幅帧落值)
      'smb2.cmd', // SMB2 命令号
      'smb2.flags.response', // 响应标志:区分请求/响应方向
      'smb2.tree', // 树连接路径
    ]) {
      expect(CAPTURE_FIELDS, `缺少字段 ${f}`).toContain(f)
    }
  })

  it('M6 第二批实测不落值/省略的字段不纳入(避免无谓放大 JSON 体积)', () => {
    // vnc.security_type 在常见 RFB 3.8 握手下实测不落值(服务端横幅帧之外取不到),
    // 纳入只会徒增 JSON 体积;smb2.filename 为省字段数省略 —— 摘要只到 tree 粒度
    for (const f of ['vnc.security_type', 'smb2.filename']) {
      expect(CAPTURE_FIELDS, `${f} 不应纳入`).not.toContain(f)
    }
  })

  it('仍不含明确后置的字段(避免无谓放大 JSON 体积)', () => {
    // 完整 RTT/窗口分析标签属后续增强;window_size_value 与 window_size 冗余,不双取
    for (const f of ['tcp.window_size_value', 'tcp.analysis.zero_window', 'tcp.analysis.window_full', 'tcp.analysis.rto']) {
      expect(CAPTURE_FIELDS, `${f} 后置,不应引入`).not.toContain(f)
    }
  })
})
