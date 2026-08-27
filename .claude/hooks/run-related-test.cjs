// PostToolUse hook: 在 Edit/Write 修改 src/** 后自动运行受影响的 vitest 测试。
// 输入：stdin 收到 ZCode hook JSON（tool_name, tool_input.file_path）。
// 行为：
//   - 测试文件本身被改   -> 只跑该测试文件
//   - 源文件被改         -> 若存在同目录同名 .test.ts(x) 则只跑它，否则跳过
//   - 非 src/、非 ts 文件 -> 跳过
// 测试失败时以 exit code 2 反馈给模型（stdout 会回传），成功静默。

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function readStdin() {
  try {
    return JSON.parse(fs.readFileSync(0, "utf8"));
  } catch {
    return null;
  }
}

const main = () => {
  const payload = readStdin();
  if (!payload) return;

  const tool = String(payload.tool_name || "");
  if (tool !== "Edit" && tool !== "Write") return;

  const filePath = String(
    (payload.tool_input && (payload.tool_input.file_path || payload.tool_input.filePath)) || ""
  );
  if (!filePath) return;

  const norm = filePath.replace(/\\/g, "/");
  if (!/\.(ts|tsx)$/.test(norm)) return;
  if (!norm.includes("/src/")) return;
  // vite.config.ts / vitest.config.ts / setup 等改动影响全量，交给全量跑
  if (/\.config\.(ts|tsx)$/.test(norm)) return;

  let testFile;
  if (/\.test\.(ts|tsx)$/.test(norm)) {
    testFile = norm;
  } else {
    const ext = norm.endsWith(".tsx") ? ".tsx" : ".ts";
    const base = norm.slice(0, -ext.length);
    [`${base}.test${ext}`, `${base}.test.ts`, `${base}.test.tsx`].some((c) => {
      if (fs.existsSync(c)) {
        testFile = c;
        return true;
      }
      return false;
    });
  }
  if (!testFile) return; // 无对应测试：跳过

  const cwd = path.resolve(__dirname, "..", "..");
  const relTest = path.relative(cwd, testFile).replace(/\\/g, "/");
  try {
    execFileSync("npx", ["vitest", "run", relTest], {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
      shell: process.platform === "win32",
      timeout: 120000,
    });
  } catch (err) {
    const out = `${err.stdout || ""}\n${err.stderr || ""}`;
    const tail = out.trim().split("\n").slice(-40).join("\n");
    console.log(`相关测试失败: ${testFile}\n${tail}`);
    process.exit(2);
  }
};

main();
