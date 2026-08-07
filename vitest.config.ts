import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.{ts,tsx}'],
    environment: 'node', // 组件测试文件顶部用 @vitest-environment jsdom 覆盖
  },
})
