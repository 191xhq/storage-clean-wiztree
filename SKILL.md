---
name: storage-clean-wiz-tree
description: >
  Windows / WSL / macOS 存储分析；Windows 优先可信 WizTree、自动检测管理员权限并通过标准 UAC 仅提升 WizTree，缺失时帮助安装，获授权后从官网部署，无授权或安装失败则 Python 回退。生成原有交互式 HTML 三级清理建议。Windows 磁盘分析优先用本增强版。扫描整机磁盘占用，找出
  占空间大户，把每一项分成 🟢可自动清理 / 🟡需人工判断 / 🔴谨慎清理 三级并给出
  可执行处置方案，生成排版精美、可折叠、命令可一键复制的交互式 HTML 报告，并可
  起本地服务在网页上一键删除（移废纸篓/直接删）。扫描全程只读。务必在以下场景
  使用：用户说"存储分析""磁盘满了""C盘/硬盘满了""空间不够""清理空间"
  "清理磁盘""占空间""哪些东西占地方""帮我看看存储""看一下电脑存储/空间"
  "存储空间""电脑空间不够""内存满了/不够/不足""看下内存/存储"（中文口语里
  "内存"常指存储空间）"storage analysis""disk cleanup""清缓存""磁盘清理"；
  或用户抱怨电脑没空间、想知道什么东西吃硬盘、想要清理建议时。注意：若用户明确
  指运行内存/RAM（如"哪个进程吃内存""内存占用高"想看活动监视器），那是 RAM
  不是存储，不属于本 skill。
---

# storage-clean-WizTree

对 Windows、WSL Windows 主机或 macOS 做只读存储分析，产出交互式 HTML 报告。Windows 存储分析优先使用本增强版。

## 铁律

- **扫描全程只读。** 不删除、移动或修改被扫描文件；允许在独立输出目录写 CSV、JSON、HTML。不得改 ACL、所有者、UAC 策略、注册表、计划任务或 WizTree 全局管理员设置，不自动清空回收站。
- **管理员扫描不意味着管理员删除。** 只允许签名有效的 WizTree 进程通过 RunAs 提权；Python、Codex、server.py 不主动提权。若 Codex 原本已提权，扫描可以继续，但 server.py 必须拒绝启动；生成静态报告，删除服务只能在普通权限 Windows 终端运行。禁止绕过拒绝检查。
- WizTree 缺失时主动帮助安装，而不是只给链接后结束。先说明使用[官网便携版](https://diskanalyzer.com/download)并检查授权：用户本轮或前文已要求“安装/帮我安装/帮助安装 WizTree”，直接完成安装，不重复询问；尚无安装授权时只询问一次，同时可继续 Python 只读分析。禁止第三方下载源、未授权静默安装或运行来源不明程序。
- **删除命令只展示，不执行。** 报告里给出的清理命令是供用户自己在终端确认后运行的。即使用户在对话里说"帮我删"，也要先停下确认（命中全局红线：删除文件必须先问），不要直接代跑。
- **估算标注清楚。** 涉及"可释放空间"一律说明是估算值。
- **路径、命令保留原文不翻译。**

## 执行流程

### Step 1 扫描（只读）

先读 Windows 分支的 [references/windows.md](references/windows.md)。Windows / WSL 固定流程：**环境检测 → WizTree 检测 → 管理员权限检测 → 必要时标准 UAC → WizTree 扫描 → CSV 解析 → 空间占用分析 → 三级分类 → HTML 报告**。UAC 取消或失败后本轮不再弹窗；使用普通模式或 Python 回退并说明遗漏。

若检测不到可信 WizTree：有明确安装授权时，先运行 `python scripts/install_wiztree.py --accept-install --download-dir <本次独立输出目录>/wiztree-install --output <本次独立输出目录>/wiztree-installation.json`，再运行 `scan.py --probe` 确认已自动识别，然后继续 WizTree 扫描。helper 只从官网动态解析当前便携版 ZIP，验证 HTTPS 来源、ZIP 路径边界和 EXE 数字签名，部署到当前用户 `%LOCALAPPDATA%\Programs\WizTree`，不改注册表/PATH/全局管理员设置、不覆盖旧安装。该 helper 用 Windows 原生 Python 执行；WSL 场景通过 Windows 主机执行同一安装步骤，不将 sudo 视为授权。安装失败或未获安装授权时保留 Python 回退，并明确下一步。

所有脚本路径以本 Skill 实际安装目录为基准；输出放独立目录，避免落入待清理项。Windows 使用 PowerShell 7、已安装 Python，不安装第三方库。

```powershell
python scripts/scan.py --probe --output storage-probe.json
python scripts/scan.py --output storage-scan.json
# 用户要求各个磁盘时，扫描全部本地固定盘；默认只详细扫描系统盘，其余固定盘仍提供容量。
python scripts/scan.py --all-fixed --output storage-scan.json
# 仅在需要定位大文件时对重点小目录导出文件级数据：
python scripts/scan.py --target 'C:\Users\Example\Downloads' --files --output focused-scan.json
```

macOS 继续 `python3 scripts/scan.py --output /tmp/storage-scan.json`；不引入 WizTree 依赖。WSL 使用 python3，扫描 Windows 主机路径可传 `C:\...` 或 `/mnt/c/...`；桥接不可用时明确警告并使用可访问挂载路径回退，不能将 sudo/root 视为 Windows 管理员。

`scan.py` 自动识别 Windows 原生、WSL、macOS 与其他 Linux：
- **macOS**：扫 home、library、caches、containers、group_containers、app_support、applications、downloads、dev_caches，用 `du` 算大小。
- **Windows / WSL 主机**：WizTree 目录 CSV 按 Allocated 统计，默认限制导出深度 8（WizTree 4.02+）、每个父目录保留 Top40；`scan_root_*` 是实际根目录排行，并尽量提供原 user_profile、appdata、temp、downloads、program_files、dev_caches 分组。默认不导出文件行，必要时重点目录 `--files`。不要把父目录与子目录大小相加。`--engine python` 可明确使用备用扫描。
- **其他 Linux / 容器**：输出 unsupported_platform；不假装完成 Windows 扫描。

输出兼容原有 `system` + `groups`，新增 `system.scan_engine`、`wiztree_version`、`wiztree_admin`、`windows_host_admin`、`scan_scope`、`scan_warnings`、`denied_paths`、`scan_issues`。根目录排行保留小项，旧热点分组通常过滤 50MB。保留这些 system 字段原样传入 analysis JSON，HTML 会显示扫描方式、范围、警告与无法读取的路径；另把 denied_paths 复制到 analysis.denied。未知权限遗漏大小写“未知”，不估造。

安装验收仅使用小型测试目录、`--probe` 或测试 fixtures，不做真实删除；实际用户请求磁盘分析时才按范围扫描。WizTree 缺失时主动提供安装帮助；已有安装授权则立即安装再扫描，未获授权时可继续 Python 扫描和报告。

### Step 2 分析与分级

先看 `system.os` 判断系统，读对应的数据布局参考：macOS 读 [references/macos.md](references/macos.md)，Windows 读 [references/windows.md](references/windows.md)（讲该系统东西存哪、怎么辨认、归哪一级）。然后读取本次 `storage-scan.json` 做这几件事：

1. **挑 Top 5** 占用大户，判定类型（系统资产/应用本体/应用数据/应用缓存/开发缓存/用户文件/媒体内容/下载内容/虚拟机镜像/回收站/其他）。
2. **识别"神秘大目录"**：UUID 命名的 Container、不明的隐藏目录，要追查它属于哪个 App、装的是什么（例如某 97GB 的 UUID Container 实为 Bilibili 离线视频缓存）。必要时 `ls`/`du` 深入一层看清楚，但仍只读。
3. **三级分类 = 清理决策清单，不是全盘点。** 只把"存在'要不要动它'这个决策"的项放进三灯；日常在用的正常应用、操作系统本身、海量零碎小文件没有清理决策，不进三灯，它们落在磁盘条的蓝色"系统及其他"里。判定标准：
   - 🟢 **可自动清理**：纯缓存、临时文件、安装包残留、明确可再生且不影响功能、不丢用户数据（pip/uv/npm/Xcode DerivedData 等开发缓存、浏览器缓存）。
   - 🟡 **需人工判断**：含用户数据或有判断成本（离线视频、文档、项目代码 node_modules、聊天记录、设计稿）。给内容画像 + 至少 3 句处置路径（应用内清理 / 系统工具 / 文件管理器手动审查，三选最合适）+ 风险提示。**所有橙灯项在服务模式下自动有「在访达/资源管理器打开」按钮**（跳过去自己审查删）；如果该项有一个核实过、删了不破坏 App 的安全子路径（如 B站离线视频的 `.Downloads` 目录、旧备份目录），给它 `trash_paths` → 网页出现「移到废纸篓」按钮（橙灯只准移废纸篓、可逆，绝不给"直接删除"）。App 托管又无安全子路径的（Chrome/微信）只给打开按钮、不给 trash_paths。按钮下方会自动写明注意事项（打开只查看不删、移废纸篓可逆需清空才释放等）；如果某项在文件管理器里是 App 内部格式、不方便手动挑选，给它一个 `open_note` 字段做客观说明（会显示在注意事项里）。**口吻要中性、像产品说明**：直接描述"这里是什么结构、为什么不好手动删、想精细操作该去哪"，不要写成"我发现/提醒注意/看着像没视频"这种暴露开发者踩坑视角的话。
   - 🔴 **谨慎清理（有决策但不建议手删）**：你可能想动、但建议别手删的具体项——重复安装的应用、想卸载的大应用、运行中应用的核心数据等。给"为什么不建议手删" + `indirect_release` 写**具体卸载步骤**（自带卸载器 / 启动台长按 / 右键移废纸篓 / AppCleaner 清残留 / App Store 可重装等，要可照做不是空话）。应用项给 `app_paths`（真实 `.app` 绝对路径数组）→ 网页出现「在文件管理器打开（去卸载）」按钮，定位到 App 让用户自己正规卸载。**红灯不给删除/卸载按钮**（应用在系统目录、可能要管理员密码、可能有自带卸载器和残留，后台代删不稳妥）。**纯系统文件、APFS 快照不要单独列红卡**（没有清理决策），归蓝色即可；系统层面的释放技巧（重启释 swap、Time Machine 快照策略、可清除空间自动回收）写进 `summary.long_term` 长期建议。

每个 🟢 项要给：预估释放空间、清理前需关闭的进程、可一键复制的清理命令（用移到废纸篓或 App 自身清理入口的安全方式，谨慎用 `rm`；如用 `rm` 必须是明确的缓存子目录）。

**大小字段写干净**：`size` / `size_estimate` 用"约 14 GB""合计约 8.6 GB"即可——"约"已表示估算，不要再加"（估算）"，重复且不专业（模板也会自动去掉这种冗余括号）。可再生属性已由分级标题和按钮说明覆盖，别塞进大小字段。

### Step 3 生成交互报告

把分析结果写成 analysis JSON（schema 见 `scripts/build_report.py` 顶部注释）。

**🟢 项必须带 `trash_paths`**（具体可删的绝对路径数组，区别于人类可读的 `path` 展示字段）——这是网页删除按钮的前提，漏了按钮就不出现。

**普通权限下默认用一键删除模式（`server.py`）打开报告**，保留用户确认机制。Windows 已提权或 WSL 服务无法安全操作 Windows 路径时使用静态报告；不得以管理员运行 server.py 或要求用户提升报告服务：
```bash
python3 scripts/server.py /tmp/storage_analysis.json   # 自动开浏览器，Ctrl+C 停
```
`server.py` 起在 127.0.0.1 + 随机端口 + 随机 token。🟢 项给「移到废纸篓」(可逆) +「直接删除」(立即释放、不可逆)；🟡 项给「在访达打开」+（有安全子路径时）「移到废纸篓」。**安全模型——三套白名单，权限从严到宽**：`rm` 只允许绿灯 `trash_paths`；`trash` 允许绿灯+橙灯 `trash_paths`（橙灯永远不能 rm）；`open`（在文件管理器打开，非破坏性）允许上述全部 + 橙灯真实 `path`。所有请求 realpath 校验 + 必须在 $HOME 内 + token + Host 校验，每次点击浏览器先 confirm。osascript/SHFileOperationW 入废纸篓，macOS 首次弹访达自动化授权点允许即可。

用户要求可分享/留存的只读文件，或 Windows 当前已提权，或 WSL 无法安全使用原生清理服务时，使用静态模式（无删除按钮，因为 `file://` 打开的页面碰不到文件系统）：
```bash
python3 scripts/build_report.py /tmp/storage_analysis.json ~/Desktop/storage-report.html && open ~/Desktop/storage-report.html
```

**排障：网页上没有删除/移废纸篓按钮**：静态报告本来没有删除按钮；只有普通权限原生环境才可改用 `server.py`。服务模式还需核对 🟢 项是否带 `trash_paths`，不扩大白名单或改为管理员运行。

报告阅读流（固定顺序）：磁盘总览卡片（容量 + 进度条 + 三色容量 pills + 系统信息，纯数据）→ 占用排行 Top5 → 执行建议 → 🟢🟡🔴 三级可折叠卡片（命令一键复制）→ 长期优化建议。即"现状 → 诊断 → 处方 → 操作 → 预防"。

注意 `summary.overview` 要写成一句话洞察（直接说最大占用是什么、能释放多少），不要重复总/已用/可用数字——那些已在卡片大数字里显示。overview 渲染在"执行建议"小节开头作引子（普通文字），紧接着是 `summary.priority` 优先级清单。

磁盘进度条把"已用"拆成分段：绿(可自动清)+橙(需手动)+红(已识别的不建议动项)+蓝(系统及其他，自动取 已用−绿−橙−红 的余量)，余下为可用(灰底)。`summary.tier_stats` 的 green / yellow / red 三个值都要以可解析的 GB 数字开头（如 "约 27.8 GB"），脚本从中取数算分段；蓝色段和"系统及其他"pill 由模板自动算余量。

pills 只渲染解析出的纯数字（如"约 5.5 GB"），不显示数据里的附注，所以 tier_stats 三个值写干净的数字即可，别加"仅已识别项/系统未计"这类道歉式说明——系统文件本来就归在蓝色段，红色只放你能量化的 🔴 项（重复应用、可卸载大应用等），量不准的系统文件/快照自然落到蓝色。

### Step 4 对话里给摘要

报告生成后，在对话里用一段话给结论先行的摘要：总可释放估算、最该先清的 2-3 项、风险最高的一项。细节让用户看网页。

## 依赖与运行前提

- 全部脚本是 **Python 3 标准库**，零第三方依赖（不用 pip install）。
- **macOS** 自带 python3、`du`、`diskutil`、`osascript`，开箱即用。
- **Windows** 默认没装 Python——需先装 Python 3，且命令多为 `python` 或 `py -3`（不是 `python3`）。本 skill 命令示例写的是 `python3`，在 Windows 上自动改用 `python` / `py -3`。
- 本 skill 是 **agent 驱动**：扫描出数据后由 agent（Claude）做分级分析，不是双击即用的独立 App。

## 平台状态

- **macOS**：扫描函数、目标目录、du 调用和 macOS 参考规则保留；本地 Windows 验收不等于 macOS 实机验证。
- **Windows**：增强扫描、服务权限隔离与模板兼容性由 tests 验证；是否完成真实 WizTree/UAC 验证以本机验收记录为准，不能由代码存在推断成功。回收站删除仅保留原实现，本次禁止真实清理测试。
- **WSL**：通过 Windows PowerShell、wslpath 和 Windows TEMP 桥接；是否有 interop、管理员身份与 WizTree 必须逐次探测。

## 长期优化建议素材（写进报告 summary.long_term）

- 定期清理：`brew cleanup`、Xcode DerivedData、浏览器缓存
- 可视化工具：DaisyDisk、GrandPerspective、OmniDiskSweeper
- 大文件归档到外置盘 / iCloud / NAS；macOS「系统设置 > 通用 > 储存空间」的优化选项
