import type { Document, Paragraph, Table } from 'docx'
import type { ReportModel } from './reportModel'
import { REPORT_SECTIONS, packetCell, parseTranscriptTableLines } from './reportModel'

/**
 * 会话分析报告 → Word(.docx)渲染。与 MD/HTML 渲染同一模型、同一章节结构。
 * - 动态 import('docx'):报告导出是低频操作,避免把 docx(含内联 JSZip)打进首屏 bundle;
 * - 字体:默认正文样式设为中文字体 Microsoft YaHei(含 eastAsia),避免中文在 Word 里回退宋体;
 * - 结构:文档标题(Title)+ Heading1 一级章节(一~四)+ Heading2 小节;表格带边框、
 *   表头行加粗且 tableHeader=true(跨页自动重复表头,与 HTML 打印样式的 thead 重复同口径);
 * - 单元格文本来自模型(mdCell 展示层已剥尖括号),docx 对 TextRun 再做 XML 转义,双保险。
 */

type DocxModule = typeof import('docx')

const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

/** 中文字体(ascii/hAnsi 覆盖西文,eastAsia 覆盖中文) */
const CN_FONT = { ascii: 'Microsoft YaHei', hAnsi: 'Microsoft YaHei', eastAsia: 'Microsoft YaHei' }

type HeadingKey = 'title' | 'heading1' | 'heading2'

function headingPara(docx: DocxModule, level: HeadingKey, text: string): Paragraph {
  const headingLevel =
    level === 'title' ? docx.HeadingLevel.TITLE : level === 'heading1' ? docx.HeadingLevel.HEADING_1 : docx.HeadingLevel.HEADING_2
  return new docx.Paragraph({ heading: headingLevel, children: [new docx.TextRun(text)] })
}

function cellPara(docx: DocxModule, text: string, bold = false): Paragraph {
  return new docx.Paragraph({ children: text ? [new docx.TextRun({ text, bold })] : [] })
}

/** 带边框表格:表头加粗 + 浅灰底 + tblHeader(跨页重复);widths 为百分比列宽(超长时均分) */
function borderedTable(docx: DocxModule, headers: string[], rows: string[][], widths: number[]): Table {
  const border = { style: docx.BorderStyle.SINGLE, size: 4, color: '999999' }
  const cellWidth = (i: number) => ({
    size: widths[i] ?? Math.floor(100 / headers.length),
    type: docx.WidthType.PERCENTAGE,
  })
  const headerRow = new docx.TableRow({
    tableHeader: true,
    children: headers.map(
      (h, i) =>
        new docx.TableCell({
          width: cellWidth(i),
          shading: { type: docx.ShadingType.CLEAR, fill: 'EFEFEF' },
          children: [cellPara(docx, h, true)],
        }),
    ),
  })
  const dataRows = rows.map(
    (r) =>
      new docx.TableRow({
        cantSplit: true, // 行内不跨页断行(与 HTML 打印样式 break-inside: avoid 同口径)
        children: headers.map((_, i) => new docx.TableCell({ width: cellWidth(i), children: [cellPara(docx, r[i] ?? '')] })),
      }),
  )
  return new docx.Table({
    width: { size: 100, type: docx.WidthType.PERCENTAGE },
    borders: { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border },
    rows: [headerRow, ...dataRows],
  })
}

function buildDocxDocument(docx: DocxModule, m: ReportModel): Document {
  const children: (Paragraph | Table)[] = []
  children.push(headingPara(docx, 'title', m.title))
  if (m.generatedAt !== null) {
    children.push(new docx.Paragraph({ children: [new docx.TextRun('生成时间: ' + m.generatedAt)] }))
  }

  children.push(headingPara(docx, 'heading1', REPORT_SECTIONS.summary))
  children.push(borderedTable(docx, ['项目', '值'], m.summary.map((f) => [f.label, f.value]), [22, 78]))

  children.push(headingPara(docx, 'heading1', REPORT_SECTIONS.findings))
  if (m.findings.note !== null) {
    children.push(new docx.Paragraph({ children: [new docx.TextRun(m.findings.note)] }))
  }
  if (m.findings.issues.length) {
    children.push(headingPara(docx, 'heading2', REPORT_SECTIONS.issues))
    children.push(
      borderedTable(
        docx,
        ['类型', '说明', '关联包号'],
        m.findings.issues.map((i) => [i.type, i.message, packetCell(i.packetNumber)]),
        [20, 62, 18],
      ),
    )
  }
  if (m.findings.stats.length) {
    children.push(headingPara(docx, 'heading2', REPORT_SECTIONS.stats))
    children.push(
      borderedTable(
        docx,
        ['标记', '次数', '首个样本'],
        m.findings.stats.map((s) => [s.flag, String(s.count), '#' + s.firstPacket]),
        [40, 20, 40],
      ),
    )
  }

  children.push(headingPara(docx, 'heading1', REPORT_SECTIONS.timeline))
  children.push(new docx.Paragraph({ children: [new docx.TextRun('当前模式: ' + m.timeline.modeLabel)] }))
  if (m.timeline.tableLines.length) {
    // 模型承载的 transcriptTableLines 原样输出,解析为结构化表格(转义还原见 parseTranscriptTableLines)
    const t = parseTranscriptTableLines(m.timeline.tableLines)
    children.push(borderedTable(docx, t.header, t.rows, [10, 12, 10, 10, 46, 12]))
  } else if (m.timeline.emptyText !== null) {
    children.push(new docx.Paragraph({ children: [new docx.TextRun({ text: m.timeline.emptyText, italics: true })] }))
  }

  children.push(headingPara(docx, 'heading1', REPORT_SECTIONS.methodology))
  for (const p of m.methodology) {
    children.push(new docx.Paragraph({ text: p, bullet: { level: 0 } }))
  }

  children.push(new docx.Paragraph({ children: [new docx.TextRun({ text: '由 pUI 导出', italics: true })] }))

  return new docx.Document({
    styles: {
      default: {
        document: { run: { font: CN_FONT, size: 21 } }, // 21 半磅 = 10.5pt(五号)
        title: { run: { font: CN_FONT, size: 36, bold: true } },
        heading1: { run: { font: CN_FONT, size: 30, bold: true }, paragraph: { spacing: { before: 280, after: 140 } } },
        heading2: { run: { font: CN_FONT, size: 24, bold: true }, paragraph: { spacing: { before: 200, after: 100 } } },
      },
    },
    sections: [{ properties: {}, children }],
  })
}

/** 打包核心:有 Buffer 全局(Node/测试/Tauri 打包)走 Packer.toBuffer,便于结构断言;
 *  浏览器(Tauri WebView)无 node:Buffer,走 Packer.toBlob 再取字节。两条路径文档内容一致。 */
async function packDocxBytes(m: ReportModel): Promise<Uint8Array> {
  const docx = await import('docx')
  const doc = buildDocxDocument(docx, m)
  if (typeof Buffer !== 'undefined') {
    return await docx.Packer.toBuffer(doc)
  }
  const blob = await docx.Packer.toBlob(doc)
  return new Uint8Array(await blob.arrayBuffer())
}

/** Word 文档字节(供测试结构断言与 Tauri 侧直写文件;浏览器内请用 renderReportDocxBlob) */
export async function renderReportDocxBuffer(m: ReportModel): Promise<Buffer> {
  return Buffer.from(await packDocxBytes(m))
}

/** Word 文档 Blob(浏览器/WebView 下载保存入口) */
export async function renderReportDocxBlob(m: ReportModel): Promise<Blob> {
  return new Blob([await packDocxBytes(m)], { type: DOCX_MIME })
}
