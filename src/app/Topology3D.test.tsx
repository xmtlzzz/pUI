// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { Topology3D } from './Topology3D'
import type { Topology } from '../stats/topology'

describe('Topology3D', () => {
  it('无 WebGL 环境(jsdom)显示降级提示而非崩溃', () => {
    const topo: Topology = { nodes: [{ id: 'a', x: 0, y: 0, host: 'a', conversations: 1, bytes: 1, issues: 0 }], edges: [] }
    const { getByText } = render(<Topology3D topo={topo} />)
    expect(getByText(/WebGL/)).toBeTruthy()
  })
})