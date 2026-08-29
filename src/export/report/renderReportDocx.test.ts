import { describe, expect, it } from 'vitest'
import { inflateRawSync } from 'node:zlib'
import { buildReportModel } from './reportModel'
import { renderReportDocxBuffer, renderReportDocxBlob } from './renderReportDocx'
import type { Conversation, Packet } from '../../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP SYN-ACK' },
  { number: 3, time: 0.5, len: 300, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'HTTP GET /', tcpAnalysis: ['retransmission'] },
  { number: 4, time: 0.6, len: 300, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'HTTP GET /', tcpAnalysis: ['retransmission', 'out-of-order'] },
  { number: 5, time: 0.7, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '2.2.2.2', dstIp: '1.1.1.1', direction: 'response', info: 'TCP ACK', tcpAnalysis: ['duplicate-ack'] },
]

const conv: Conversation = {
  id: 'k', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'http', packetCount: 5, bytes: 780,
  start: 0, end: 0.7, duration: 0.7, packets,
  issues: [{ type: 'retransmission', message: '观察到 2 次 TCP 重传', packetNumber: 3 }],
}

interface ZipEntry {
  name: string
  method: number // 0 = store,8 = deflate
  data: Buffer | null
}

/** 顺序走查 zip 局部文件头(docx 由 JSZip 顺序写出):PK\x03\x04 头定长 30 字节,文件名不压缩。
 *  字段偏移:flags@+6 method@+8 compSize@+18 nameLen@+26 extraLen@+28,文件名@+30。
 *  仅用于测试结构断言,不做完整 zip 解析。 */
function zipEntries(buf: Buffer): ZipEntry[] {
  const out: ZipEntry[] = []
  let off = 0
  while (off + 30 <= buf.length && buf.readUInt32LE(off) === 0x04034b50) {
    const flags = buf.readUInt16LE(off + 6)
    const method = buf.readUInt16LE(off + 8)
    const compSize = buf.readUInt32LE(off + 18)
    const nameLen = buf.readUInt16LE(off + 26)
    const extraLen = buf.readUInt16LE(off + 28)
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8')
    const dataStart = off + 30 + nameLen + extraLen
    let data: Buffer | null = null
    if (!(flags & 0x08) && compSize > 0) {
      data = buf.subarray(dataStart, dataStart + compSize)
      off = dataStart + compSize
    } else {
      // 数据描述符形态(大小字段为 0):扫描下一个局部头签名找边界
      const next = buf.subarray(dataStart).indexOf('PK\x03\x04', 0, 'latin1')
      off = next === -1 ? buf.length : dataStart + next
    }
    out.push({ name, method, data })
  }
  return out
}

function inflateEntry(entries: ZipEntry[], name: string): string {
  const e = entries.find((x) => x.name === name)
  if (!e) throw new Error('zip 缺少成员: ' + name)
  if (!e.data) throw new Error('成员无定长压缩数据,无法解包: ' + name)
  return e.method === 0 ? e.data.toString('utf8') : inflateRawSync(e.data).toString('utf8')
}

describe('renderReportDocx — 会话分析报告 Word 渲染', () => {
  it('Buffer 以 PK 开头且包含 word/document.xml(zip 局部头文件名不压缩,可直接 indexOf)', async () => {
    const buf = await renderReportDocxBuffer(buildReportModel(conv))
    expect(buf.length).toBeGreaterThan(0)
    expect(buf.subarray(0, 2).toString('latin1')).toBe('PK')
    expect(buf.indexOf('word/document.xml')).toBeGreaterThan(-1)
  })

  it('zip 成员齐全:Content_Types / rels / document / styles', async () => {
    const buf = await renderReportDocxBuffer(buildReportModel(conv))
    const names = zipEntries(buf).map((e) => e.name)
    for (const must of ['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml']) {
      expect(names).toContain(must)
    }
  })

  it('document.xml 可解包,含标题与四级章节(Heading1/Heading2 渐进层级)', async () => {
    const buf = await renderReportDocxBuffer(buildReportModel(conv))
    const xml = inflateEntry(zipEntries(buf), 'word/document.xml')
    expect(xml).toContain('<w:document')
    expect(xml).toContain('会话分析报告')
    for (const s of ['一、报告概要', '二、异常与发现', '三、会话时序', '四、证据口径与限制', '会话异常', 'TCP 分析标记统计']) {
      expect(xml).toContain(s)
    }
    // 标题样式引用:Heading1(一级章节)+ Heading2(小节)
    expect(xml).toContain('w:val="Heading1"')
    expect(xml).toContain('w:val="Heading2"')
  })

  it('正文表格带边框与重复表头(表头行 w:tblHeader)', async () => {
    const buf = await renderReportDocxBuffer(buildReportModel(conv))
    const xml = inflateEntry(zipEntries(buf), 'word/document.xml')
    expect(xml).toContain('<w:tbl>')
    expect(xml).toContain('w:tblBorders')
    expect(xml).toContain('<w:tblHeader/>')
  })

  it('默认正文字体为中文字体 Microsoft YaHei(含 eastAsia)', async () => {
    const buf = await renderReportDocxBuffer(buildReportModel(conv))
    const styles = inflateEntry(zipEntries(buf), 'word/styles.xml')
    expect(styles).toContain('Microsoft YaHei')
    expect(styles).toContain('w:eastAsia="Microsoft YaHei"')
  })

  it('概要事实与统计数值进入正文;生成时间可选', async () => {
    const withAt = inflateEntry(
      zipEntries(await renderReportDocxBuffer(buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' }))),
      'word/document.xml',
    )
    for (const s of ['1.1.1.1', '2.2.2.2', 'http', '780B', '0.000~0.700s', '生成时间: 2026-08-29 10:00:00']) {
      expect(withAt).toContain(s)
    }
    const without = inflateEntry(zipEntries(await renderReportDocxBuffer(buildReportModel(conv))), 'word/document.xml')
    expect(without).not.toContain('生成时间')
  })

  it('不可信抓包内容不得以未转义标签进入文档 XML(mdCell 展示层剥除 + docx XML 转义)', async () => {
    const evil: Packet[] = [
      { number: 9, time: 1, len: 60, transport: 'tcp', proto: 'http', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request',
        info: 'HTTP GET /a|b<img src=x onerror=alert(1)>`q`' },
    ]
    const evilConv: Conversation = { ...conv, packets: evil, packetCount: 1, bytes: 60, end: 1, duration: 1, issues: [] }
    const xml = inflateEntry(zipEntries(await renderReportDocxBuffer(buildReportModel(evilConv))), 'word/document.xml')
    expect(xml).not.toContain('<img')
    expect(xml).toContain('onerror=alert(1)') // 文本保留,仅为安全文本
  })

  it('renderReportDocxBlob 与 Buffer 同内容(解包 document.xml 逐字一致),MIME 为 docx', async () => {
    // 注:docx 包经 JSZip 打包时文件时间取当前时刻,zip 容器字节非跨调用逐字节稳定;
    // 内容等价性用可解包的 document.xml 逐字比较(两侧同一文档内容)。
    const m = buildReportModel(conv)
    const buf = await renderReportDocxBuffer(m)
    const blob = await renderReportDocxBlob(m)
    expect(blob.type).toBe('application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    const bytes = Buffer.from(await blob.arrayBuffer())
    expect(bytes.subarray(0, 2).toString('latin1')).toBe('PK')
    expect(inflateEntry(zipEntries(bytes), 'word/document.xml')).toBe(inflateEntry(zipEntries(buf), 'word/document.xml'))
  })

  it('确定性:同输入两次渲染,document.xml 逐字一致(容器时间戳除外)', async () => {
    const m = buildReportModel(conv, { generatedAt: '2026-08-29 10:00:00' })
    const a = inflateEntry(zipEntries(await renderReportDocxBuffer(m)), 'word/document.xml')
    const b = inflateEntry(zipEntries(await renderReportDocxBuffer(m)), 'word/document.xml')
    expect(a).toBe(b)
  })
})
