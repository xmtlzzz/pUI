import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.{ts,tsx}'],
    environment: 'node', // 组件测试文件顶部用 @vitest-environment jsdom 覆盖
    // 重测试(3.2 万包聚合/2000 行渲染)在并发下接近 5s 上限,偶发超时是资源抖动
    // 而非回归 —— 全局放宽到 10s,避免不同慢测试在并发跑时随机超时
    testTimeout: 10000,
  },
})
