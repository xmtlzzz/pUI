# emotion-ball（vendored）

来源：https://github.com/sam70361/aora-bot （`emotion-ball/js/`）

## 引入内容

- `js/rings.js`、`js/emotions.js`、`js/ball.js`、`js/engine.js` — 官方引擎四件套，**原样引入，未做任何修改**（升级时整目录替换）。
- `boot.js` — pUI 自己的接入层（创建实例 `emotion:'36' 联网加载`、tips 同步、销毁钩子），不属于上游。
- 上游 `css/`、`assets/`、`docs/`、展示站（`i18n.js`/`app.js`）未引入（宿主接入不需要，README 明确说明）。

## 许可要点（摘要，以仓库 LICENSE / NOTICE.md 原文为准）

- **引擎源代码与表情配置数据**：独立编写，双许可 —— 个人学习研究免费；商业用途需按上游 `LICENSE-COMMERCIAL.md` 取得授权。
- **球形角色视觉形象**（blob/wedge/gem 造型、配色、特效）：仅限个人学习研究，**禁止商用**，上游声明"不提供、也永不提供商业授权"。

pUI 当前按个人学习研究用途引入。**若 pUI 未来商用分发，必须先移除本目录或取得上游商业授权**——此约束同时适用于打包产物（引擎文件会随 `public/` 进入 dist 与安装包）。

## 接入位置

- `index.html`：按官方顺序加载四件套 + `boot.js`，容器 `#boot-ball`。
- `src/main.tsx`：React 首帧后调用 `window.__puiBootTeardown()`（引擎 `destroy()` 停 RAF）再移除启动层。
