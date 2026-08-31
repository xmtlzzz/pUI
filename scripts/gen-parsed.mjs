import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'

/**
 * 用真实 tshark 以 -e 精选字段模式重新生成示例抓包的 parsed JSON。
 * 字段清单与 src/parse/captureFields.ts、src-tauri/src/tshark.rs CAPTURE_FIELDS 三处保持一致
 * (前端 parsePackets 同时兼容旧的全协议树形态,但新产物一律走平铺形态)。
 *
 * Run: node scripts/gen-parsed.mjs
 */

import { readFileSync } from 'node:fs'

const TSHARK = process.env.TSHARK ?? (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\tshark.exe' : 'tshark')
const OUT = join(process.cwd(), 'public', 'fixtures')
const EXAMPLES = ['http', 'dns', 'mixed', 'lossy', 'remote', 'dual-a', 'dual-b']

// 从 src/parse/captureFields.ts 提取字段清单(单文件无依赖,直接正则取字符串字面量)。
// 字符集必须含大写字母:rdp.negReq.requestedProtocols 是 Wireshark 官方注册名(camelCase),
// 曾因只认小写被静默漏抓;契约测试 captureFields.contract.test.ts 按集合相等钉住本正则。
const captureFieldsSrc = readFileSync(join(process.cwd(), 'src', 'parse', 'captureFields.ts'), 'utf-8')
const FIELDS = [...captureFieldsSrc.matchAll(/'([A-Za-z0-9_.]+)'/g)].map((m) => m[1])
if (FIELDS.length < 30) throw new Error(`captureFields.ts 解析异常,仅得 ${FIELDS.length} 个字段`)

const eArgs = FIELDS.flatMap((f) => ['-e', f])
// 与 Rust run_capture 同步:关闭相对序号,让 seq/ack/SACK 统一落在 raw 空间
// (默认相对序号会让 sack_le 与 seq_raw 处于不同空间,比较后造出假 Gap)
const OPTS = ['-o', 'tcp.relative_sequence_numbers:FALSE']

mkdirSync(join(OUT, 'examples', 'parsed'), { recursive: true })
mkdirSync(join(OUT, 'parsed'), { recursive: true })

for (const name of EXAMPLES) {
  const pcap = join(OUT, 'examples', `${name}.pcapng`)
  const json = execFileSync(TSHARK, [...OPTS, '-r', pcap, '-T', 'json', ...eArgs], { maxBuffer: 256 * 1024 * 1024 })
  writeFileSync(join(OUT, 'examples', 'parsed', `${name}.json`), json)
  if (name === 'http') writeFileSync(join(OUT, 'parsed', `${name}.json`), json) // 浏览器回退 fixture
  console.log(`parsed: ${name}.json (${(json.length / 1024).toFixed(1)}KB)`)
}
console.log('done')
