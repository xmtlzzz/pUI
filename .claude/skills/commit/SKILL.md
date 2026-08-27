---
name: commit
description: 验证（全量测试）后按项目 commit 规范提交当前改动。用户手动调用。
disable-model-invocation: true
argument-hint: [可选：附加的 commit message 说明]
---

# /commit — 验证并提交

严格按顺序执行，任何一步失败即停止并向用户报告，不跳步、不自动修复超出本 skill 范围的问题。

## 1. 确认改动范围

```
git status --short
git diff --stat
```

- 若工作区无任何改动：告知用户无事可做，结束。
- 若存在用户可能不知情的文件（如临时文件、`.claude/settings.local.json` 之类本地配置），列出并在提交信息中只纳入与本次工作相关的改动。

## 2. 全量验证

```
npx vitest run
```

- 必须全部通过。失败的测试正是本次改动的相关模块时，尝试最小修复后重跑；否则停下向用户报告失败输出。
- 若改动涉及 `src-tauri/`（Rust），另跑 `cargo check`（在 `src-tauri/` 下执行）。
- 若改动涉及 `src/**/*.ts(x)`，另跑 `npx tsc --noEmit`。

## 3. 提交

message 规范（参考 git log 既有风格，中文、带里程碑前缀）：

- 新功能：`feat(M<N>): <一句话>`
- 修复：`fix(<scope>): <一句话>`
- 文档/进度：`docs: <一句话>`
- 测试补充：`test(<scope>): <一句话>`

- 标题 ≤ 50 字符，正文可补充动机与验证方式（注明 `npx vitest run` 通过的用例数）。
- 只 add 与本次工作相关的文件，明确列出 `git add <paths>`，不用 `git add -A`。
- 不 push，除非用户在参数中明确要求。
