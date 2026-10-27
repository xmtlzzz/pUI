# 2026-10-27 首页发布验证

## Git 起始状态

仓库已存在并关联 `https://github.com/xmtlzzz/pUI.git`，分支为 `main`。工作区起始时干净；执行 `git fetch origin` 后，`git rev-list --left-right --count HEAD...origin/main` 输出 `2 0`。本地已有但尚未推送的提交：

- `2bf9ecb`：列式编解码、Worker 与流式解析可靠性修复。
- `8fed3ea`：按 requestId 取消 Tauri 流式解析。

源码和配置均已纳入本地 Git。依赖、构建目录、临时探针、CodeGraph 缓存等本地生成物保持忽略。

## 本地回归

| 命令 | 真实结果 |
| --- | --- |
| `npx vitest run` | 88 files / 888 tests passed；最终一次全量耗时 27.16 s |
| `npx vitest run site/` | 2 files / 11 tests passed |
| `npm run build` | TypeScript strict 与桌面 Vite 构建通过，121 modules |
| `npm run build:site` | TypeScript strict 与官网 Vite 构建通过，14 modules |
| `cargo test --manifest-path src-tauri/Cargo.toml` | 30 passed / 0 failed，含真实 tshark 流式读取与取消测试 |
| `git diff --check` | exit 0 |

官网数据模型按先失败后实现的顺序开发。测试覆盖帧号与会话数据保真、缺失字段、确定性、示例切换、报文点选和功能介绍入口。首次与 Rust 编译并发跑全量时，一个既有 DOM 大列表用例触发 10 秒超时；编译结束后两次全量均通过，未放宽测试超时或削弱断言。

桌面构建保留原有 Tauri 模块的静态/动态混用打包提示，不影响构建退出码。

## Cloudflare 实际部署

- Worker：`pui-home`。
- 线上地址：`https://pui-home.xmtlzloveasuka.workers.dev/`。
- 最终版本：`adc009eb-451b-45de-8d79-4ec0fa1bd6bb`。
- 最终部署命令 `wrangler deploy` 退出码 0，输出 `Uploaded pui-home`、`Deployed pui-home triggers` 及上述 URL/版本。
- 网络存在间歇性连接超时。发布重试保留 TLS 证书验证，没有修改系统代理、关闭证书验证或把凭据写入项目。

通过真实 HTTPS 请求下载以下资源，逐个 SHA-256 比对本地最终构建，全部一致：

| 路径 | HTTP | 大小 |
| --- | --- | --- |
| `/` | 200 | 17,901 B |
| `/assets/index-L6hBKwDM.js` | 200 | 30,630 B |
| `/assets/index-CQn0RfX3.css` | 200 | 25,317 B |
| `/favicon.svg` | 200 | 294 B |
| `/robots.txt` | 200 | 88 B |
| `/sitemap.xml` | 200 | 175 B |
| `/this-page-does-not-exist` | 404 | 378 B，与本地 `404.html` 一致 |

首页 SHA-256：`905233a6a913625cf5053d4c2c66780b21f7c39a847f333c6fbbe69497e182d2`。

## 浏览器验收与边界

线上页面实际加载成功，最终 DOM 中 canonical 与 CSS/JS 哈希文件名与本地构建一致。真实交互结果：

- HTTP 示例：11 个报文、1 个会话。
- DNS 示例：2 个报文，Seq/Ack 均显示 `unavailable`。
- TCP 示例：5 个报文，默认选中重传标签帧；点击帧 #1 后显示该帧字段。
- FAQ 展开状态可切换。
- 检查 1440×1000 桌面视口及 390×844 手机视口，手机 document scrollWidth 为 375，小于视口宽度，无横向溢出；完整页面截图确认各节与页脚布局。

官网只演示内置合成抓包；未把此验收描述为任意用户 PCAP 的浏览器解析能力。没有创建新桌面安装包；下载入口继续指向 GitHub 当前 Releases。
