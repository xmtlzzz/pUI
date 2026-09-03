// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

// 真实 http.hex.txt fixture(113 字节,8 行):GET 帧 hex dump,与下方 packet 同帧
const HEX = readFileSync(resolve(process.cwd(), 'public/fixtures/parsed/http.hex.txt'), 'utf-8')

const mocks = vi.hoisted(() => ({
  selectSelectedPacket: vi.fn(),
  useApp: vi.fn(),
}))

vi.mock('../state/appStore', () => ({
  useApp: mocks.useApp,
  selectSelectedPacket: mocks.selectSelectedPacket,
}))
vi.mock('../app/EmotionBallLoader', () => ({
  EmotionBallLoader: () => null,
}))

import { PacketDetail } from './PacketDetail'
import type { Packet } from '../model/types'

/** GET 帧(与 http.hex.txt 一致):len=113,tcpLen=59 → 应用层区域 [54,113) */
function packet(): Packet {
  return {
    number: 4,
    time: 1,
    len: 113,
    capLen: 113,
    transport: 'tcp',
    proto: 'http',
    srcIp: '192.168.1.10',
    dstIp: '93.184.216.34',
    srcPort: 54321,
    dstPort: 80,
    srcMac: '00:11:22:33:44:55',
    dstMac: '00:aa:bb:cc:dd:ee',
    httpMethod: 'GET',
    httpUri: '/',
    tcpLen: 59,
    direction: 'request',
  }
}

function renderDetail() {
  mocks.selectSelectedPacket.mockReturnValue(packet())
  mocks.useApp.mockImplementation((sel: (s: { fetchHexFor: () => Promise<string>; getHex: () => string | null }) => unknown) =>
    sel({ fetchHexFor: () => Promise.resolve(''), getHex: () => HEX }),
  )
  return render(<PacketDetail />)
}

describe('PacketDetail hex 字节联动', () => {
  beforeEach(() => {
    mocks.selectSelectedPacket.mockReset()
    mocks.useApp.mockReset()
  })

  afterEach(() => {
    cleanup()
  })

  it('hex dump 渲染并带 data-testid,协议树标题可点击', () => {
    renderDetail()
    const pre = screen.getByTestId('detail-hex')
    expect(pre.textContent).toContain('0000')
    expect(pre.textContent).toContain('0010')
    expect(screen.getByTestId('detail-title-app')).toBeTruthy()
  })

  it('点击「应用层」标题 → hex 高亮应用层区域并滚动到首行', () => {
    renderDetail()
    fireEvent.click(screen.getByTestId('detail-title-app'))
    // 应用层 [54,113):字节 54 落在 0x30 行(数据行下标 3)
    const hlLine = screen.getByTestId('detail-hex-line-3')
    expect(hlLine.getAttribute('data-highlighted')).toBe('true')
    // 非应用层行不高亮
    expect(screen.getByTestId('detail-hex-line-0').getAttribute('data-highlighted')).toBeNull()
    // 滚动到首行(下标 3 × 行高)
    const pre = screen.getByTestId('detail-hex') as HTMLElement
    expect(pre.scrollTop).toBe(3 * 16)
  })

  it('hover 传输层标题 → 高亮对应区域,移开清除', () => {
    renderDetail()
    const title = screen.getByTestId('detail-title-tcp')
    fireEvent.mouseEnter(title)
    // tcp 区域 [34,54):字节 34 落在 0x20 行(数据行下标 2)
    expect(screen.getByTestId('detail-hex-line-2').getAttribute('data-highlighted')).toBe('true')
    fireEvent.mouseLeave(title)
    expect(screen.getByTestId('detail-hex-line-2').getAttribute('data-highlighted')).toBeNull()
  })

  it('点击应用层叶子字段(HTTP 方法)→ 继承所在层区域高亮', () => {
    renderDetail()
    fireEvent.click(screen.getByTestId('detail-field-app.http'))
    expect(screen.getByTestId('detail-hex-line-3').getAttribute('data-highlighted')).toBe('true')
  })
})
