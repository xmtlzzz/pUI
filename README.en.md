# pUI · Packet Flow Sequence Analyzer

**pUI** is a cross-platform (Windows / macOS / Linux) desktop packet analyzer built on Tauri 2 + React, using Wireshark's `tshark` as the parsing engine. Open a capture, filter by protocol / address / port / issue type, automatically aggregate bidirectional conversations, and render packet interactions as a timestamped sequence diagram. Beyond the classic sequence view it ships a **TCP byte-stream state engine**: it derives explainable fault events and stages from the evidence chain of gaps / SACK / retransmissions, keeps observation strictly separated from inference, and exports evidence reports as Markdown / Word / PDF / HTML.

简体中文 · [English](README.en.md)

## ✨ Features

### Core conversation analysis

- **Open captures**: pcap / pcapng / **cap** (the classic suffix exported by tcpdump and network devices) plus gzip-compressed variants, 5views / NetMon / nettl / snoop / CommView / Sniffer / ERF / btsnoop and more — tshark detects formats by content magic, regardless of extension; drag-and-drop or dialog, 5 built-in examples; real interface count, parse time and tshark version in the overview
- **Conversation-level filtering**: protocol, src/dst IP, src/dst port, negation, issues-only, per-issue-type refinement (retransmission / out-of-order / dup-ACK / lost segment / zero window / SYN retransmission / slow response / no-close / RST / unanswered request / connection never established / one-way), configurable slow-response threshold
- **Bidirectional aggregation**: 5-tuple normalization (with `tcp.stream` identity), automatic client/server detection (IPv4 / IPv6 / MAC), robust to mid-stream captures and missing ports
- **Sequence diagram**: styles A (diagonal) / B (lifeline), relative/absolute timestamps, idle-gap segment navigation for long captures, auto-downsampling beyond 2000 packets, search & time-window highlight
- **Packet detail**: layered collapsible tree (Frame → L2 → L3 → L4 → Application) + hex dump (streamed per frame)
- **Multi-view**: Sessions / Hosts (top talkers, anomalies) / Summary (protocol mix, RTT percentiles, window stats, health score, application events) / Topology (draggable, click-through)
- **Time drill-down**: traffic histogram; clicking a bucket auto-locates the busiest conversation in that window

### TCP fault analysis (M0-M7)

- **Sequence-space engine**: RFC1982 32-bit arithmetic, raw sequence space, pairwise SACK parsing, full gap lifecycle (reveal / SACK coverage / fill / persistence), mid-stream detection
- **Event engine**: suspected loss/delay, reordering, suspected ACK-loss/spurious retransmission, zero window, RST, SYN retransmission — each event carries an evidence chain (Observed / Inference / Limitation), deterministic ids, unrecovered-first ordering
- **Fault/normal comparison page**: sequence-space graphics (seen-bytes bar, gap hatching, SACK blocks, retransmission arrow, ACK cursor resting at its final position), gap-neighborhood/panorama views, pointer-anchored wheel zoom + drag pan, legend-as-layer-toggle, stage band (name / packet range / timing / summary always visible), multi-event switcher (windowed virtualization beyond 60 events), key-packet jump with stage restore, time-window correlation with application-layer events (limited wording: may be related, does not imply causation)
- **Application analyzers**: HTTP / DNS / TLS / **SSH / RDP / VNC / SMB2** as pluggable analyzers — encrypted protocols are observed only through plaintext handshake/command fields; no reassembly, no decryption
- **Performance**: Rust-side frame-boundary streaming for large files (frontend parses per batch with live frame-count progress); worker-pooled JSON parsing on the frontend (pool = min(4, CPU cores)); a 5000-retransmission storm (~15k packets) analyzes in <3s

### Reports & evidence

- **Session reports in three formats**: Markdown / Word (.docx, standard progressive headings) / PDF (print preview via the WebView's native print-to-PDF, vector CJK text with system fonts); "compact transcript" merges consecutive identical packets, "anomalies only" lists flagged packets for week reports
- **Event evidence**: Markdown report + versioned JSON evidence (schema `pui-evidence`, deterministic) + **offline single-file HTML** (fully escaped, zero scripts, zero remote resources, inline print CSS) — all three share one input contract, semantically consistent
- **Data-fidelity red lines**: the "normal reference" panel is explanatory illustration and never enters observations/evidence/exports; missing byte counts render as unknown, never as 0

## 🧱 Tech stack

| Layer | Tech |
|---|---|
| Desktop shell | [Tauri 2](https://tauri.app/) (Rust) |
| Frontend | React 19 · TypeScript (strict) · Vite 7 · Zustand 5 |
| Parsing engine | tshark (Wireshark CLI; tested against 4.6+) |
| Extras | Boot-screen emotion-ball (official engine vendored verbatim, see NOTICE) · `docx` lazy-loaded |
| Tests | Vitest 4 (593 cases) · Rust `cargo test` (25 cases incl. real-tshark e2e) |

## 📦 Prerequisites

- **tshark** (Wireshark CLI) — resolved in order: user-set path → bundled resource → `PATH` → common install locations. Install Wireshark or point the app at tshark in settings.
- **Rust** (cargo) and **Node.js** (≥ 18), plus the platform's WebView2.

## 🚀 Build & run

```bash
npm install

npm run tauri dev      # development (HMR)
npm run tauri build    # production bundle (msi / nsis)

npm test               # frontend tests (currently 593 cases)
cargo test --manifest-path src-tauri/Cargo.toml   # Rust tests (currently 25 cases)
npx vitest run src/analysis/tcp/perfGuard.test.ts # performance guard (e2e skipped without tshark)
```

> The packaged app is a console-less GUI; child processes use `CREATE_NO_WINDOW` so no console windows flash.
> CI: GitHub Actions (vitest + build + cargo test on push/PR); a local `.githooks/pre-push` runs the same gates (enable with `git config core.hooksPath .githooks`).

## 📖 Usage

1. **Open**: toolbar button or drag-and-drop (cap / pcapng / pcap and compressed variants all work), or pick a built-in example.
2. **Filter**: left panel — protocol / IP / port, negation, issues-only, issue types, slow-response threshold.
3. **Browse**: sortable/searchable conversation list; sequence diagram with styles, timestamps and segment navigation; click packets for layered detail + hex.
4. **Fault analysis**: with a conversation selected, click "⚠ Fault analysis" to enter the comparison page — sequence-space graphics, stage-band selection, key-packet jumps; "view event context" in packet detail jumps straight to the matching event, and returning restores event + stage exactly.
5. **Export**: diagram PNG; session report (choose Markdown / Word / PDF); on the comparison page "Export report / evidence JSON / HTML".
6. **Views**: Sessions / Hosts / Summary / Topology; click a histogram bucket in Summary to drill down.

## 🎯 Built-in examples

| Example | Content |
|---|---|
| `http` | full HTTP request/response with teardown |
| `dns` | DNS query/response |
| `mixed` | ARP + DNS + HTTP mix |
| `lossy` | loss scenario: retransmission + unanswered request (full fault-analysis demo) |
| `remote` | SSH / VNC / RDP / SMB2 real handshakes (application-analyzer demo) |

## 🗂️ Project structure

```
src/             frontend (React + Zustand)
  parse/         tshark JSON → Packet model (three-way field contract)
  analysis/      TCP byte-stream engine · event engine · stage derivation · app analyzers
  aggregate/     conversation aggregation + issue flags
  m4/            comparison-page view models · zoom/animation pure functions
  render/        sequence layout & rendering
  app/           layout · toolbar · filters · list · views · fault comparison page
  export/        PNG · session reports (md/docx/html) · event evidence (md/json/html)
  bridge/        Tauri IPC + browser fallback
  state/         global Zustand store
src-tauri/       Rust backend (commands + tshark process management + streaming + hardening)
public/fixtures  built-in example captures
docs/            PRD · architecture · decisions · plan · reviews
scripts/         fixture & icon generators
```

## 📚 Docs

See [docs/README.md](docs/README.md) for the PRD, architecture, key decisions, implementation plan and adversarial reviews.

## 📄 License

[MIT](LICENSE). Third-party note: the boot animation engine and character artwork in `public/emotion-ball/` are licensed by their upstream for personal study/research only (commercial use requires separate permission — see that directory's NOTICE.md).

---

*Built for packet-level troubleshooting & teaching. Issues and PRs welcome.*
