# pUI 产品首页部署

产品首页：https://pui-home.xmtlzloveasuka.workers.dev/

源码仓库：https://github.com/xmtlzzz/pUI

## 构建边界

- `src/` + `src-tauri/`：现有桌面工具，`npm run build` 输出 `dist/`。
- `site/`：独立产品首页，`npm run build:site` 输出 `dist-site/`；不会替换桌面入口。
- 官网复用 `parsePackets`、`aggregateConversations`，读取仓库中的 HTTP、DNS、TCP 重传合成示例。帧号、时间与字段来自实际解析结果；字段缺失显示 `unavailable`。
- 官网不接收用户抓包，不提供浏览器端任意 PCAP 解析；完整分析功能使用本机 tshark 和桌面工具。
- 官网未引入桌面加载动画或第三方远程字体、分析脚本。桌面端第三方组件的许可边界仍以仓库 NOTICE 为准。

## 本地运行

```sh
npm ci
npm run dev:site
# http://127.0.0.1:4174/

npm test
npm run build
npm run build:site
cargo test --manifest-path src-tauri/Cargo.toml
```

`vitest.config.ts` 将官网行为测试纳入前端全量测试，`tsconfig.json` 同时严格检查桌面与官网源码，CI 额外检查官网构建。

## 发布到 Cloudflare

使用 Cloudflare Workers Static Assets。`wrangler.jsonc` 声明独立 Worker `pui-home`，只上传 `dist-site/`。无数据库、上传服务或服务器端抓包处理。

```sh
npx wrangler@4.125.0 login
npm run deploy:site
```

登录使用本机 Wrangler 管理的凭据；不要将凭据、`.env`、`.wrangler/` 或构建产物加入 Git。网络需要代理时，仅在当前终端设置 `HTTPS_PROXY`。登录状态、网络连接和账号权限应在发布时重新核对。

`site/public/_headers` 提供 CSP、防嵌入和 MIME 检查等响应头；静态资源文件名带哈希并长期缓存。未知路径返回独立 404 页面。首页具有 canonical、Open Graph、robots 和 sitemap。

发布后核对 Wrangler 返回的线上地址与版本，实际请求首页、CSS、JS、favicon、sitemap 和未知路径；在浏览器中切换三个示例、点击报文、展开 FAQ，并检查桌面与手机视口。`--dry-run` 只验证打包，不能证明线上成功。

## GitHub 与发布

项目已有公开仓库及 `main` 分支。推送前执行前后端全量测试、桌面构建和官网构建；本地 pre-push hook 还会运行前端测试、桌面构建及 Rust 测试。Cloudflare 发布为单独命令，GitHub CI 当前负责检查，不自动部署，也不需要在仓库中配置发布密钥。

下载按钮指向 GitHub Releases 的 `latest` 地址。官网发布不等于生成新的桌面安装包；可下载的平台与版本以 Releases 实际附件为准。
