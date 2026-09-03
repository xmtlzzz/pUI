import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parseHexLayout, locateByte, rangeToLines } from './hexLayout'

/** 48 字节的合成 hex dump(3 行 × 16 字节),列格式与 tshark -x 一致 */
const HEX = [
  '0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................',
  '0010  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  ................',
  '0020  20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f   !"#$%&\'()*+,-./',
].join('\n')

describe('parseHexLayout', () => {
  it('逐行解析 offset 与字节列位置', () => {
    const lines = parseHexLayout(HEX)
    expect(lines.map((l) => l.offset)).toEqual([0, 16, 32])
    expect(lines.map((l) => l.byteCount)).toEqual([16, 16, 16])
    expect(lines[0].bytePos.length).toBe(16)
    expect(lines[0].bytePos[0]).toBe(6) // offset 列(6 字符)之后是第一个字节
    expect(lines[0].bytePos[15]).toBe(51)
    expect(lines[0].text.slice(lines[0].bytePos[0], lines[0].bytePos[0] + 2)).toBe('00')
    expect(lines[0].text.slice(lines[0].bytePos[15], lines[0].bytePos[15] + 2)).toBe('0f')
  })

  it('0-15 边界:字节 0 与 15 落在第 0 行', () => {
    expect(locateByte(HEX, 0)).toEqual({ line: 0, byteIndex: 0 })
    expect(locateByte(HEX, 15)).toEqual({ line: 0, byteIndex: 15 })
  })

  it('16-31 边界:字节 16 与 31 落在第 1 行', () => {
    expect(locateByte(HEX, 16)).toEqual({ line: 1, byteIndex: 0 })
    expect(locateByte(HEX, 31)).toEqual({ line: 1, byteIndex: 15 })
  })

  it('越界/负偏移返回 null', () => {
    expect(locateByte(HEX, 48)).toBeNull()
    expect(locateByte(HEX, -1)).toBeNull()
  })

  it('末行不完整(截断帧)只解析实际字节数', () => {
    const partial = '0070  0a                                                .\n'
    const lines = parseHexLayout(partial)
    expect(lines[0].offset).toBe(0x70)
    expect(lines[0].byteCount).toBe(1)
    expect(locateByte(partial, 0x70)).toEqual({ line: 0, byteIndex: 0 })
    expect(locateByte(partial, 0x71)).toBeNull()
  })

  it('跳过空行等非数据行', () => {
    const lines = parseHexLayout('0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ....\n\n')
    expect(lines).toHaveLength(1)
  })

  it('5 位 offset(>64KB 帧)也能解析', () => {
    const big = '10000  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99  ................\n'
    const lines = parseHexLayout(big)
    expect(lines[0].offset).toBe(0x10000)
    expect(lines[0].byteCount).toBe(16)
    expect(lines[0].bytePos[0]).toBe(7)
  })

  it('真实 fixture(http.hex.txt,113 字节)逐行对齐', () => {
    const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/parsed/http.hex.txt'), 'utf-8')
    const lines = parseHexLayout(raw)
    expect(lines.length).toBe(8)
    expect(lines[0].offset).toBe(0)
    expect(lines[0].byteCount).toBe(16)
    expect(lines[lines.length - 1].offset).toBe(0x70)
    expect(lines[lines.length - 1].byteCount).toBe(1)
  })
})

describe('rangeToLines 字节范围 → 逐行高亮区间', () => {
  it('跨行范围拆分成行内区间', () => {
    expect(rangeToLines(HEX, 14, 18)).toEqual([
      { line: 0, from: 14, to: 16 },
      { line: 1, from: 0, to: 2 },
    ])
  })

  it('单行内范围', () => {
    expect(rangeToLines(HEX, 0, 4)).toEqual([{ line: 0, from: 0, to: 4 }])
  })

  it('空范围/越界返回空数组', () => {
    expect(rangeToLines(HEX, 48, 49)).toEqual([])
    expect(rangeToLines(HEX, 10, 10)).toEqual([])
  })
})
