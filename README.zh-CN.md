# FlowBrake

[English](README.md) | [简体中文](README.zh-CN.md)

![FlowBrake 应用图标](assets/app-icon.png)

FlowBrake 是使用 Rust 编写的 Windows 网络限速工具，通过 WinDivert 拦截
TCP/UDP 流量，用 Windows IP Helper API 识别进程，并提供 Slint 桌面界面。
本仓库仅包含 Rust 版本。

## 功能

- 全局、进程组及单个 PID 的下载与上传限速
- 按可执行文件名分组，双击展开 PID
- 全局与进程流量阻断、自适应限速、独立下载/上传丢包及固定延迟模拟
- 实时速度、活动规则和按阻断/丢包/限速分类的丢包统计
- 详情侧栏及 TCP 连接列表；IPv4 连接支持单个或批量断开
- 可选 IPv6 统计与限速、进程图标、系统托盘、自定义窗口
- 标准单位与 ISP 单位切换，简体中文与英文即时切换
- 保存进程组规则、全局规则、语言、窗口位置及其他偏好

## 环境与启动

运行要求为 Windows 10/11 x64 和管理员权限。下载 ZIP 后完整解压，保留
`FlowBrake.exe`、`WinDivert.dll` 和 `WinDivert64.sys` 在同一目录，再启动 EXE。
如 Windows 显示 SmartScreen，请先确认下载来源，再按系统提示操作。
应用使用管理员清单，启动时需批准 UAC；拒绝提权会退出。

拦截器在批准提权后自动启动。输入速度后，勾选对应的下载或上传开关才会应用
限速；仅输入数值会保留为草稿。点击行打开详情侧栏，双击进程组展开实例。
运行时关闭窗口会进入系统托盘，可从托盘打开窗口或退出。

IPv4 始终参与拦截。设置中的 IPv6 开关控制 IPv6 统计与限速；IPv6 阻断及
丢包及延迟模拟独立于此开关。IPv6 连接可查看，目前无法从应用中断开。

## 语言与数值输入

在设置中选择 **跟随系统 / 简体中文 / English**，立即更新界面及托盘，保留
规则和未提交输入，并保存语言偏好。默认跟随系统：`zh-CN`、`zh-SG` 和显式
`zh-Hans` 区域使用简体中文；英文及未支持区域回退英文。`zh-TW`、`zh-HK`、
`zh-MO` 和 `zh-Hant` 回退英文。跟随系统在启动及选择该选项时解析；更改
Windows 语言后，重新选择该项或重启应用。

译文内嵌于 EXE，无需联网或单独下载语言包。UAC、SmartScreen 和原始系统
错误详情的语言由 Windows 决定。

语言不改变数值含义：小数点使用 `.`。标准 `KB/s` 按 1024 字节计算，ISP
`Kb/s` 按 1000 比特计算；内部限速保存为整数 KiB/s，输入时按此精度取整。
统计与限速均按 TCP/UDP 有效载荷字节计算，空 TCP 控制包不占限速预算。

## 阻断与丢包模拟

阻断结合套接字过滤与数据包丢弃，阻止新的外部连接及已有外部流量；保留本机
回环流量。全局阻断还覆盖 ICMP。它不会关闭网卡，已有 TCP 连接可能在超时前
继续显示。进程归属依赖端口到 PID 的映射；无法解析或归属的数据包无法保证
按进程阻断。套接字过滤安装失败时，状态栏显示阻断保护降级。

在全局行、进程组或 PID 的详情中，分别设置下载与上传丢包率，范围为 0–100，
最多两位小数。按 Enter 或离开输入框生效；非法输入显示错误，保留已有规则。

- 进程留空：继承该方向的全局丢包率；显式 `0`：覆盖并关闭该进程的模拟。
- 全局留空或 `0`：关闭全局模拟。进程值替代全局值，不重复抽样。
- 覆盖可解析的外部 IPv4/IPv6 TCP/UDP，包括空控制包和重传；回环不受影响。
- `100` 会形成数据包黑洞，但不安装套接字阻断过滤器，连接可能等待超时。
- 未归属进程的数据包使用全局值；不支持解析的数据包不参与模拟。

执行顺序为阻断 → 丢包模拟 → 限速准入 → 延迟 → 发送前再次检查阻断。模拟丢包不消耗限速预算。显示的丢包率
是引擎启动以来，模拟丢弃数与非零丢包规则抽样包数的累计比例；不计阻断包、
回环及显式 0% 规则。已抽样后因限速丢弃的包仍计入分母。随机结果在短时间内
可能偏离设置值；同时启用限速会增加总丢包。仅测试丢包时建议关闭自适应限速。
全局与进程组丢包规则持久化，PID 覆盖仅限当前会话。

## 固定延迟模拟

在原详情侧栏分别设置**下载延迟 ms / 上传延迟 ms**，范围为 `0..=5000`
的整数毫秒。按 Enter 或离开输入框提交；非法输入不改变生效规则和已保存配置。
延迟独立生效，不需要勾选速度限制。

- 进程某方向留空继承全局，显式 `0` 覆盖关闭；全局留空或 `0` 不增加延迟。
  进程值替代全局值，不相加。
- 编辑进程组会更新当前全部子 PID 并保存名称模板；新发现且没有 PID 规则的
  进程复制模板，已有 PID 覆盖保持不变。PID 规则只在当前会话生效，名称模板
  不是运行期逐字段的第三级继承。
- 覆盖可解析的外部 IPv4/IPv6 TCP/UDP，包括空 TCP 控制包；回环不增加延迟。
  不支持 ICMP/ping 延迟。无法识别 PID 时只应用全局延迟，仍受现有端口归属精度限制。
- 数值是**单向延迟**，不是 RTT。无重传和过载时，上下行各 `100 ms`，
  单次请求/响应的 RTT 约增加 `200 ms`。

仅需等待的包进入队列，同方向同流保持顺序。这不是新的带宽整形器：现有限速
仍按准入/丢弃实现，出队不重复执行丢包抽样和限速扣费。队列上限包括正在发送
的包：全局 **64 MiB / 16384 包**，单 PID **8 MiB / 4096 包**；未知 PID
使用独立共享额度。达到任一限制即丢弃新入队包。这些是原始包数据额度，不是
应用整体 RSS 上限；高吞吐或长延迟可能产生额外的队列溢出丢包。

状态栏保留阻断/丢包/限速计数，并分别显示累计延迟包数、当前队列包数/原始
字节数、队列溢出、发送失败、停止弃包、引擎错误及阻断保护降级。
非零延迟变更只影响新包，已排队包保留原截止时间；有效延迟改为零或清除规则
时，适用积压按序释放。正常停止/退出先停止捕获，取消额外等待并排空已捕获包，
再关闭驱动；发送前仍检查当前阻断规则。失败不计为成功发送，异常无法送回的
包单独计数。重启清空队列与计数，但保留已保存规则。

真实延迟测试需要管理员 PowerShell，以及受控的非回环 TCP 服务器，服务器须
将收到的字节原样回显：

```powershell
$env:FLOWBRAKE_DELAY_TEST_ENDPOINT = "<external_IP>:<TCP_port>"
cargo test -p flowbrake-windows live_process_delay -- --ignored --nocapture
```

该测试检查 TCP RTT 及延迟流量下的停止行为。当前终端未提权、未配置回显端点，
真实 RTT、停止恢复和驱动行为仍待验证；单元测试不能替代这些结论。

## 配置保存

配置位于 `%APPDATA%\FlowBrake\settings.ini`，采用 `key=value` 格式，保存语言
（`language=system|zh-CN|en`）、速度单位、IPv6、窗口状态、展开组及全局与按
可执行文件名保存的规则。旧配置未指定语言或值非法时采用跟随系统。
匹配进程再次出现时恢复进程组规则；关闭窗口、进入托盘或修改相关偏好时保存。
双向延迟保存在 `global.download_delay_ms`、`rule.example.exe.upload_delay_ms`
等现有键中；含点的可执行文件名完整往返。缺失或非法延迟字段视为未覆盖，
显式 `0` 会保存。降级前备份配置：旧版忽略延迟字段，并可能在保存时丢弃它们。

## 构建与检查

开发需安装 Rust stable MSVC 工具链及 Visual Studio Build Tools / Windows SDK，
确保 `link.exe` 和 `rc.exe` 可用。

```powershell
cargo build --workspace
cargo run -p flowbrake-ui
```

完整检查与发布打包：

```powershell
cargo fmt --all -- --check
.\scripts\check-translations.ps1
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p flowbrake-ui --release
.\scripts\package-windows.ps1
```

构建脚本内嵌图标与管理员清单，并将 WinDivert DLL 和驱动复制到 EXE 旁边。
ZIP 输出为 `dist/FlowBrake-windows-x64-v<version>.zip`，附 SHA-256 文件；包内
包含 EXE、DLL、驱动、中英文 README 及 LICENSE。当前发布形式为 ZIP。
Windows 下请在管理员 PowerShell 中运行工作区测试，UI 测试程序会继承应用的管理员权限清单。

CI 在推送、PR 及手动触发时检查格式、译文、测试及 Clippy；`v*` 标签还构建
并上传发布包和校验和。

需要管理员与真实外网连接的驱动集成测试默认忽略。具备条件时，可在管理员
PowerShell 中设置可访问的外部 TCP 服务器地址运行：

```powershell
$env:FLOWBRAKE_TEST_ENDPOINT = "<external-IP>:<port>"
cargo test -p flowbrake-windows live_process_block -- --ignored --nocapture
```

测试只阻断自身 PID，检查回环及连接恢复，结束后清理过滤器。

## 翻译维护

资源目录为 `crates/flowbrake-ui/lang/`，包含英文 POT 模板和
`zh-CN/LC_MESSAGES/flowbrake-ui.po`。界面文案用 Slint `@tr(...)` 标记；Rust
生成的动态文案放在 `ui/translations.slint`，使用同一翻译目录。保留参数、
复数规则、进程名、协议名及单位。`src/i18n.rs` 中的启动提权提示是界面创建前
使用的一小组双语文案，独立维护和测试，不属于 PO 目录。

修改文案后更新 POT 与 PO。可选用匹配当前 Slint 版本的官方翻译提取工具生成
POT，也可手动维护；检查脚本核对源文案、POT 和 PO 是否一致。执行
`scripts/check-translations.ps1`，构建后检查中英文主窗口、设置、侧栏、
错误提示及托盘。检查最小窗口及 Windows 缩放下是否缺字或遮挡。新增语言
还需加入设置选项与系统区域映射，单独添加 PO 不会使语言可选。

## 已知限制与许可

基于丢包的限速在极低速度下可能导致 TCP 超时或连接不稳定；固定包延迟不将
其替换成排队式带宽整形。进程规则受端口到 PID 映射限制，TCP 断开仅支持 IPv4。当前不提供
安装器或签名驱动分发流程。更新 WinDivert 时须同时替换
`third_party/windivert/` 下的 DLL 与驱动；如杀毒软件告警，先核实组件来源。

本项目使用 Apache License 2.0，见 [LICENSE](LICENSE)。
