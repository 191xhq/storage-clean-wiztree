# storage-clean-WizTree

> 只读磁盘占用分析 + 三级清理决策报告的 agent skill。Windows 优先调用可信的 WizTree 拿到全盘真实占用；没有 WizTree 也能用纯 Python 扫。产出单文件交互式 HTML 报告，命令一键复制。macOS / WSL 同样可用。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#依赖与运行前提)

---

## 它解决什么问题

"磁盘满了"这类请求，工具能给你一棵树，但给不了判断：这 40 GB 到底能不能删、删了会不会出问题、该用哪个入口删。

这个 skill 把两件事分开做：

1. **测量**（脚本）——只读扫描，拿到真实占用，谁大谁小一目了然。
2. **判断**（agent）——识别每一项是什么、能不能再生、删了有什么代价，分成三级给出可执行的处置路径。

最终产物是一份能对着操作的报告，不是一张让人更焦虑的饼图。

## 三级分类怎么分

| 级别 | 含义 | 判定标准 |
|---|---|---|
| 🟢 **可自动清理** | 纯缓存、临时文件、安装包残留 | 明确可再生、不影响功能、不丢用户数据 |
| 🟡 **需人工判断** | 含用户数据或有判断成本 | 离线视频、文档、项目代码、聊天记录、设计稿 |
| 🔴 **谨慎清理** | 有决策但不建议手删 | 应用本体、系统目录——给正规卸载步骤，不代跑 |

**三灯是清理决策清单，不是全盘点。** 没有"要不要动它"这个决策的东西（操作系统本身、日常在用的应用、海量零碎小文件）不进三灯，它们落在磁盘条的蓝色「系统及其他」里。

## 快速开始

```bash
git clone https://github.com/191xhq/storage-clean-wiztree.git
cd storage-clean-wiztree
```

### 1. 探测环境

```powershell
python scripts/scan.py --probe --output storage-probe.json
```

告诉你：什么系统、是不是管理员、有没有可信的 WizTree（含版本与数字签名校验结果）、各个固定盘的容量。

### 2. 扫描

```powershell
# 只详细扫系统盘（默认），其余固定盘仍给容量
python scripts/scan.py --output storage-scan.json

# 扫全部固定盘
python scripts/scan.py --all-fixed --output storage-scan.json

# 对重点小目录导出文件级数据，定位大文件
python scripts/scan.py --target 'C:\Users\Example\Downloads' --files --output focused-scan.json

# 明确走 Python 回退，不用 WizTree
python scripts/scan.py --engine python --output storage-scan.json
```

### 3. 生成报告

分析结果写成 analysis JSON（schema 见 [`scripts/build_report.py`](scripts/build_report.py) 顶部注释），然后二选一：

```bash
# A. 一键删除模式：本地服务，🟢 项有「移到废纸篓 / 直接删除」按钮
python scripts/server.py storage-analysis.json

# B. 静态只读报告：单个 HTML 文件，无删除按钮，便于分享留存
python scripts/build_report.py storage-analysis.json storage-report.html
```

静态报告用 `file://` 打开，页面碰不到文件系统，所以没有删除按钮——这是设计如此，不是 bug。

## 报告长什么样

阅读顺序固定为 **现状 → 诊断 → 处方 → 操作 → 预防**：

1. **磁盘总览卡片**——容量、进度条（按三色分段）、系统信息，纯数据。
2. **占用排行 Top 5**——最大的五个东西，以及它们各是什么类型。
3. **执行建议**——一句话洞察 + 优先级清单。
4. **🟢🟡🔴 三级可折叠卡片**——每张卡带命令，一键复制。
5. **长期优化建议**——避免下次再满。

报告是单文件 HTML，零外部依赖，不联网，可以直接发给别人看。

## 安全模型

这个工具会碰到删除操作，所以边界写死：

- **扫描全程只读。** 不删、不移、不改被扫描的文件；只在独立输出目录写 JSON / CSV / HTML。
- **管理员扫描 ≠ 管理员删除。** 只允许签名有效的 WizTree 进程通过标准 UAC 提权；Python 脚本自身从不提权。当前进程已经是管理员时，`server.py` 会**拒绝启动**，只允许生成静态报告——删除服务必须在普通权限终端里跑。
- **三套白名单，权限从严到宽：**
  - `rm`（直接删除）→ 只允许 🟢 项的 `trash_paths`
  - `trash`（移入回收站）→ 允许 🟢 + 🟡 的 `trash_paths`；🟡 永远不能 `rm`
  - `open`（在文件管理器打开，非破坏性）→ 上述全部 + 🟡 的真实 `path`
- **每次请求都校验：** realpath 归一 + 必须在 `$HOME` 内 + 会话 token + Host 头，浏览器端每次点击前二次确认。
- **服务只绑 `127.0.0.1`**，随机端口 + 随机 token，会话结束即失效。
- **红灯永不提供删除/卸载按钮**，只给"打开文件管理器去正规卸载"。
- 不自动清空回收站，不改 ACL / 所有者 / UAC 策略 / 注册表 / 计划任务。

## WizTree 与隐私

Windows 上优先用 [WizTree](https://diskanalyzer.com/download)（便携版）扫描，因为它通过读取 NTFS MFT 拿真实分配大小，快且准。

- 缺失时，`scripts/install_wiztree.py` 可以从官网动态解析当前便携版 ZIP 并部署到 `%LOCALAPPDATA%\Programs\WizTree`。
- 只接受 `diskanalyzer.com` 及其官方 CDN 主机，校验 HTTPS 来源、ZIP 路径边界和 EXE 的 Authenticode 数字签名。
- 不改注册表、不改 PATH、不动 WizTree 的全局管理员设置、不覆盖已有安装。
- 安装需要显式授权：`--accept-install`。不装也能用 `--engine python` 扫描，只是慢一些、粒度粗一些。

**扫描数据不出本机。** 所有解析、分级、报告生成都在本地完成。报告里出现的是你自己的路径，分享前请自己过一眼——这个工具不替你脱敏。

## 平台支持

| 平台 | 扫描引擎 | 状态 |
|---|---|---|
| **Windows** | WizTree（管理员 MFT）/ Python os.scandir 回退 | 主力支持，有测试覆盖 |
| **WSL** | 桥接 Windows 主机执行 WizTree | 支持；interop、管理员身份、WizTree 需逐次探测 |
| **macOS** | `du` | 支持；扫描函数与参考规则保留，未做 macOS 实机全量验收 |
| 其他 Linux / 容器 | — | 明确返回 `unsupported_platform`，不假装完成 |

WSL 场景下 `sudo`/`root` **不等于** Windows 管理员，这是两套权限体系，代码里按这个假设实现。

## 作为 skill 使用

这是一个 **agent 驱动**的 skill，不是双击即用的独立 App：脚本负责测量，agent 负责判断和写报告。

把整个目录放到你的 skills 目录下（例如 `~/.agents/skills/storage-clean-WizTree/`），`SKILL.md` 的 frontmatter 就会被识别。`agents/openai.yaml` 提供 OpenAI 风格客户端的界面元数据。

目录结构：

```
.
├── SKILL.md                    # 主流程：铁律 → 扫描 → 分级 → 报告 → 摘要
├── agents/openai.yaml          # 客户端界面元数据
├── assets/report_template.html # 单文件报告模板（数据由脚本注入）
├── references/
│   ├── windows.md              # Windows 数据布局与归类规则
│   └── macos.md                # macOS 数据布局与归类规则
├── scripts/
│   ├── scan.py                 # 平台探测 + 扫描 + 输出 JSON
│   ├── wiztree.py              # WizTree 调用与 CSV 解析
│   ├── wiztree_host.ps1        # Windows 侧执行器（提权只在这里发生）
│   ├── install_wiztree.py      # 官网便携版下载、验签、部署
│   ├── build_report.py         # analysis JSON + 模板 → 静态 HTML
│   └── server.py               # 本地一键删除服务（含白名单与权限隔离）
└── tests/                      # unittest，零依赖
```

## 测试

```bash
python -m unittest discover -s tests -v
```

24 个测试，覆盖 CSV 解析（含中文路径、UTF-16、硬链接去重、截断拒绝）、WSL 路径桥接、UAC 不重复弹窗、HTTP 白名单与 token 校验、以及管理员环境下 `server.py` 必须拒绝启动。测试不执行真实删除。

## 依赖与运行前提

- 全部脚本是 **Python 3 标准库**，零第三方依赖，不用 `pip install`。
- **Windows** 命令是 `python` 或 `py -3`（不是 `python3`）。文档示例写 `python3`，在 Windows 上自行替换。
- **macOS** 自带 `python3`、`du`、`diskutil`、`osascript`，开箱即用。
- 首次用 `server.py` 的「移到废纸篓」时，macOS 会弹访达自动化授权，点允许即可。

## 已知限制

- WizTree 导出的 CSV 受子目录索引上限影响（默认 10000 个父目录）。超大目录树需要针对重点路径做 `--target` 定向扫描。
- WizTree CSV 无法证明每个受保护目录都被读到；报告里的 `denied_paths` 与 `scan_warnings` 会如实标出，未知的部分不编造数字。
- NTFS 元数据、快照、重解析点可能与卷标称已用空间有差异。
- 「可释放空间」都是**估算值**，报告里统一用"约 N GB"表述。

## 贡献

Issue 和 PR 都欢迎。涉及删除路径的改动请一并更新 `tests/test_safety.py`——白名单和权限隔离是这个项目最不该退化的部分。

## License

[MIT](LICENSE)
