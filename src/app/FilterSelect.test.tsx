// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'
import { FilterSelect } from './FilterSelect'

afterEach(cleanup) // 菜单经 portal 挂到 body,必须显式清理,否则跨用例残留重复节点

describe('FilterSelect 键盘可达性', () => {
  it('ArrowDown 打开菜单并高亮首个选项,Enter 切换之', () => {
    const onToggle = vi.fn()
    const { getByRole } = render(<FilterSelect title="协议" options={['http', 'dns', 'tcp']} current={[]} onToggle={onToggle} />)
    const trigger = getByRole('button', { name: /\+ 添加/ })
    trigger.focus()
    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
    expect(trigger.getAttribute('aria-activedescendant')).toBeTruthy()
    fireEvent.keyDown(trigger, { key: 'Enter' })
    expect(onToggle).toHaveBeenCalledWith('http')
  })

  it('ArrowUp 从关闭态循环到最后一个选项', () => {
    const onToggle = vi.fn()
    const { getByRole } = render(<FilterSelect title="协议" options={['http', 'dns', 'tcp']} current={[]} onToggle={onToggle} />)
    const trigger = getByRole('button', { name: /\+ 添加/ })
    trigger.focus()
    fireEvent.keyDown(trigger, { key: 'ArrowUp' })
    fireEvent.keyDown(trigger, { key: 'Enter' })
    expect(onToggle).toHaveBeenCalledWith('tcp')
  })

  it('Escape 与 Tab 都会关闭菜单', () => {
    const onToggle = vi.fn()
    const { getByRole } = render(<FilterSelect title="协议" options={['http']} current={[]} onToggle={onToggle} />)
    const trigger = getByRole('button', { name: /\+ 添加/ })
    trigger.focus()
    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('已选 chip 是可聚焦按钮且可点击移除', () => {
    const onToggle = vi.fn()
    const { getByRole } = render(<FilterSelect title="协议" options={['http']} current={['http']} onToggle={onToggle} />)
    const chip = getByRole('button', { name: /移除 http/ })
    fireEvent.click(chip)
    expect(onToggle).toHaveBeenCalledWith('http')
  })
})
