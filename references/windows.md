# Windows 数据布局与分级参考

分析 Windows 扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。
每次探测本机环境与实际扫描结果，不能将模拟测试或 macOS 运行视为 Windows WizTree 实测。

## WizTree 引擎与权限

Windows 流程：环境检测 → WizTree 检测 → WindowsPrincipal 管理员检测 → 必要时 RunAs 标准 UAC → 扫描等待完成 → CSV 解析 → 原 JSON 分析与分级 → HTML。

`scripts/wiztree_host.ps1` 在 PATH、HKCU/HKLM App Paths、32/64 位卸载安装信息、Program Files (x86)、LocalAppData/Programs、常见 Tools/WizTree 路径和桌面/开始菜单快捷方式中有界查找，不遍历全盘。候选必须文件存在、文件版本 >=3.18、产品与公司匹配 WizTree/Antibody，且 Authenticode 签名 Valid、签发主体含 Antibody Software。无法验证就跳过并记录，绝不执行。有效候选先选 WizTree64.exe，再按数值版本降序；无64位才考虑 wiztree.exe。64位系统上的32位引导程序会派生64位子进程，因此对它使用 Start-Process -Wait 等待进程树；Python 外层仍限定总超时。超时或导出校验失败则回退，不能读半成品。

找不到可信安装：主动提供官网便携版安装帮助，检查本轮与前文授权。用户已要求帮助安装时，直接运行 `scripts/install_wiztree.py --accept-install --download-dir <独立目录> --output <安装记录.json>`，不重复索要确认。未授权时只询问一次，分析可用 Python 继续。helper 从 https://diskanalyzer.com/download 动态获取官方 ZIP 地址，限定 HTTPS 官方域及重定向，校验 ZIP 路径与签名后部署到 `%LOCALAPPDATA%\Programs\WizTree`。已有目标不覆盖，保留下载包、SHA-256 与签名证据；不执行全局安装器，不改注册表、PATH 或全局配置。安装后重新 probe 并切回 WizTree。安装失败则明确记录原因并保留 Python 备用方案。

官网 ZIP 当前跳转到其官方 CDN `antibodysoftware-17031.kxcdn.com`，安装 helper 仅接受这个精确 CDN 主机，不放行任意 kxcdn 子域。若当前网络 TLS 握手失败，可用 `--tls12` 兼容模式（仍校验证书与主机名）；已有本地代理时可显式 `--proxy http://127.0.0.1:<端口>` 仅作用于本次请求，不修改系统设置。Windows 原生 curl 备用传输用 `--transport windows-curl`，逐跳校验官方域和 HTTP 状态，不把 301 HTML 当 ZIP。只有官方包路径检查及 Authenticode 均通过后才部署和执行。

管理员判断使用 WindowsIdentity + WindowsPrincipal.IsInRole(Administrator)，与 WSL sudo/root 无关。已管理员直接启动不加 RunAs；非管理员仅给 WizTree 设置 Start-Process -Verb RunAs。参数作为数据传递，使用 Windows argv 引号规则，支持中文、空格、&、单引号、美元符号等。取消/失败只重试一次 /admin=0，后续盘不再触发 UAC。报告的 admin_evidence 记录继承已提权令牌或标准 RunAs 成功，不能声称扫描覆盖了所有受保护对象。

WizTree 命令参数依据[官方命令与 CSV 文档](https://diskanalyzer.com/guide)：

```text
WizTree64.exe "C:" /export="<unique.csv>" /admin=1 /exportfolders=1 /exportfiles=0 /sortby=2 /exportmaxdepth=8
```

`/exportmaxdepth` 从 4.02 起支持，见[官方版本记录](https://diskanalyzer.com/whats-new)。旧版只使用基础参数并记录导出可能较大。默认目录级导出，重点目录可 `--target <folder> --files`。默认扫描系统盘；`--all-fixed` 扫全部本地固定盘。Win32_LogicalDisk DriveType=3 排除网络盘、光驱、可移动设备。每个作用域有独立 CSV 和完成状态。扫描进程退出、退出码成功、导出非空且可独占打开后才解析；超时、缺根行、缺表头或非法大小均视为失败，回退并保留警告。

Python 标准库 csv 流式读 CSV，识别 UTF-8 BOM、UTF-16 或系统 ANSI 编码、元信息前缀、表头顺序变化及中英文别名。优先 Allocated；缺失则逻辑大小并警告。目录末尾反斜杠或属性16识别目录；目录总量直接使用原值，不递归相加。文件 Allocated 前导0按官方 hardlink 约定计零，避免额外重复占用。每父目录仅保留 Top40，最多10000个父目录索引并明确截断警告；深度限制也必须写进 scan_scope。深处热点应再定向扫描，不能把未导出的行解释为空目录。

Python 回退记录所有 PermissionError/OSError 的路径，保留 partial 项，跳过符号链接和 Junction/reparse point。其数值为逻辑字节，硬链接、压缩/稀疏文件和元数据可能导致偏差。权限遗漏体量未知，不能把 0 当成确认没有占用。

## WSL 主机桥接

`wiztree.py` 检测 Microsoft 内核或 WSL_DISTRO_NAME。通过 powershell.exe -NoProfile -NonInteractive -EncodedCommand 执行同一只读 Windows helper；请求 JSON 以 UTF-8/base64 传入，路径不拼进 shell 命令。不修改 PowerShell 执行策略。Linux/Windows 路径通过 wslpath -w/-u 转换；默认 CSV 在 Windows TEMP 的独立目录，WSL 可通过挂载读取。Windows 主机运行 WizTree/UAC 并等待导出，Linux Python 仅解析结果。

interop 不可用或 Windows PowerShell 失败：记录原因，使用可访问的 /mnt/c 等挂载路径 Python 回退；不假造管理员状态或主机扫描成功。WSL 根权限不能提升 Windows。WSL 扫描所得 Windows 路径不要直接交给 Linux server.py 清理；使用静态报告或普通权限 Windows 原生服务。

## 报告与安全边界

保留完整 system 扫描元信息进入 analysis JSON：scan_engine、wiztree_version、wiztree_admin、scan_scope、scan_warnings、denied_paths、scan_issues。HTML 显示引擎、是否管理员扫描、实际范围、权限与导出警告；组大小不可累加造成重复计算。

WizTree 管理员仅用于读取；server.py 在管理员 Windows 会直接拒绝启动，HTTP 动作也二次拒绝。此时用 build_report.py 输出静态 HTML。非管理员服务仍绑定127.0.0.1、随机端口和 token，保留 Host 校验、三套白名单、realpath、HOME 边界与浏览器确认。绿灯才可直接删，黄灯仅移回收站，红灯只打开；管理员扫描不扩大任何白名单。扫描不修改用户文件，不清回收站，不改 ACL/注册表/系统策略。

## 多盘符

Windows 通常多个盘（C:、D:…）。磁盘总览会列出所有盘，但**分析和清理聚焦系统盘 C:**——缓存、AppData、临时文件几乎都在 C:。其他盘（D: 等）一般是用户自存的资料/游戏，归 🟡 让用户自己判断，不要自动给删除按钮。

## 关键目录

| 目录（环境变量） | 装什么 | 典型分级 |
|---|---|---|
| `%LOCALAPPDATA%`（`C:\Users\<u>\AppData\Local`） | 浏览器缓存、应用数据、Temp，最大头 | 缓存 🟢 / 应用数据 🟡 |
| `%LOCALAPPDATA%\Temp`、`%TEMP%` | 临时文件 | 🟢 |
| `%APPDATA%`（Roaming） | 应用配置/数据 | 🟡 |
| 浏览器缓存 `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache`、Edge 同构 | 浏览器缓存 | 🟢 |
| 浏览器 `User Data\<Profile>`（非 Cache 部分） | 书签/登录态 | 🟡 |
| `%USERPROFILE%\.cache`、`.npm`、`.gradle`、`.m2`、`.nuget\packages`、`%LOCALAPPDATA%\pip\Cache`、`Yarn` | 开发缓存 | 🟢 |
| `C:\Program Files`、`Program Files (x86)` | 应用本体 | 🔴 仅重复/想卸时上灯，否则归蓝色 |
| `%USERPROFILE%\Downloads` 的安装包 | exe/msi 残留 | 🟢 |
| `C:\$Recycle.Bin` | 回收站 | 🟡 提示用户清空 |

## 系统占用（不上灯，归蓝色"系统及其他"，间接释放写 long_term）

- `C:\Windows\WinSxS`：组件存储，**绝不能手删**，用 `DISM /Online /Cleanup-Image /StartComponentCleanup`
- `C:\Windows\SoftwareDistribution\Download`：Windows Update 缓存，用磁盘清理处理
- `hiberfil.sys`（休眠）、`pagefile.sys`（虚拟内存）：系统管理，别手动删
- 间接释放：设置 > 系统 > 存储 > 存储感知；`cleanmgr`（磁盘清理）；扩展磁盘清理选 Windows 更新清理

## 删除机制

`server.py` 在 Windows 用 ctypes 调 `SHFileOperationW`(FOF_ALLOWUNDO) 送进回收站；纯标准库。🟢 项的 `trash_paths` 应在用户配置文件（`%USERPROFILE%`）目录内，便于白名单与 HOME 越界校验通过。
