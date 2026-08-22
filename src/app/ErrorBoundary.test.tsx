// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { ErrorBoundary } from './ErrorBoundary'

function Bomb(): never {
  throw new Error('boom-detail')
}

describe('ErrorBoundary', () => {
  it('子组件抛错时显示可读错误而非白屏', () => {
    const { getByText, getByRole } = render(
      <ErrorBoundary name="报文详情">
        <Bomb />
      </ErrorBoundary>,
    )
    expect(getByRole('alert')).toBeTruthy()
    expect(getByText(/渲染出错/)).toBeTruthy()
    expect(getByText(/boom-detail/)).toBeTruthy()
    const retry = getByRole('button', { name: /重试/ })
    expect(retry).toBeTruthy()
  })
})