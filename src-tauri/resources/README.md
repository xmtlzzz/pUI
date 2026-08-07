# 打包期内置 tshark(发布构建时可选)

应用在运行时按以下顺序定位 tshark:**用户设置路径** → **随包内置资源** → **系统 PATH** → **常见安装目录(Wireshark)**。因此即使不内置 tshark,装了 Wireshark 的机器也能直接用。

**v1 默认不内置**:`tauri.conf.json` 未配置 `bundle.resources`,开发与构建无需额外文件;运行时回退到系统 Wireshark。

## 若要在发布安装包中内置 tshark

1. 把目标平台的 tshark 及其运行依赖(Windows 下还需 `libwireshark*.dll`、`libwiretap*.dll`、`libwsutil*.dll`、`libglib-2.0-0.dll`、`libgmodule-2.0-0.dll` 等)一并放入 `src-tauri/resources/`。
2. 在 `tauri.conf.json` 的 `bundle` 段加入:

```jsonc
"resources": {
  "resources/tshark.exe": "tshark.exe"
}
```

3. 重新 `tauri build`。注意:tauri-build 会把缺失的 resource 当作硬错误,所以必须先把二进制放好再构建。

二进制**不提交到 git**(见 `.gitignore`)。

**随包分发合规**:tshark 为 GPL-2.0 开源软件,以子进程方式调用、未修改/未链接其代码,
分发安装包时应随附 Wireshark 的 GPL 许可证文本(见 `docs/research/参考实现与竞品分析.md`)。
