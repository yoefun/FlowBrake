# FlowBrake

[English](README.md) | [简体中文](README.zh-CN.md)

![FlowBrake app icon](assets/app-icon.png)

FlowBrake is a lightweight Windows network limiter written in Rust. It uses
WinDivert to intercept IPv4 and optional IPv6 TCP/UDP traffic, maps packets back
to owning processes with the Windows IP Helper API, and provides a Slint-based
desktop UI for per-process and global throttling.

This repository contains the Rust rewrite only. The earlier C# / WinForms
implementation and generated .NET publish artifacts have been removed.

## Features

- Per-process download and upload limits in KB/s (or Kb/s in ISP units)
- Global download and upload limits for all traffic
- Process grouping by executable name, with optional per-PID expansion
- Block-all switches for global or per-process traffic
- Adaptive mode that adjusts token-bucket rates toward the configured target
- Live rolling speed display with a status-bar summary of throughput and active rules
- TCP connection list in the detail sidebar, with per-connection and bulk disconnect (IPv4)
- Detail sidebar for editing limits, block, and adaptive settings on the selected row
- Process icons loaded from executable paths
- Optional IPv6 interception and connection listing (enabled by default)
- Speed display in ISP units (Kb/s) or standard units (KB/s)
- Persistent settings for rules, window geometry, expanded groups, and preferences
- System tray support while the interceptor is running
- English and Simplified Chinese, with saved language preference and live switching
- Custom frameless window chrome with DWM rounded corners
- Windows GUI executable with embedded icon and `requireAdministrator` manifest

## Platform Support

FlowBrake is Windows-only.

Requirements:

- Windows 10/11 x64
- Administrator privileges at runtime
- Rust stable toolchain with the MSVC target
- Visual Studio Build Tools / Windows SDK, including `link.exe` and `rc.exe`

IPv4 TCP/UDP traffic is always intercepted. IPv6 support is optional and can be
toggled in Settings. When IPv6 is disabled, IPv6 packets are passed through
unchanged.

## Repository Layout

```text
crates/flowbrake-core/      Shared rules, token bucket, formatting, grouping
crates/flowbrake-windows/   WinDivert, IP Helper, packet parsing, engine loop
crates/flowbrake-ui/        Slint UI, tray integration, settings, app state
  ui/main.slint             Main window, process table, detail sidebar
  ui/window_chrome.slint    Custom title bar and settings dropdown
  ui/widgets.slint          Shared checkbox and control widgets
assets/                     Compile-time application resources
third_party/windivert/      Runtime WinDivert DLL and driver files
scripts/package-windows.ps1 Release zip packaging script
```

## Building

Install Rust and a Windows MSVC toolchain, then run:

```powershell
cargo build --workspace
```

For an optimized GUI executable:

```powershell
cargo build -p flowbrake-ui --release
```

The UI build script embeds `assets/app.ico` into the Windows executable and
copies these runtime files next to the executable:

- `WinDivert.dll`
- `WinDivert64.sys`

The executable uses a `requireAdministrator` manifest so Windows shows the UAC
prompt when the app is launched. If the process is not already elevated, FlowBrake
also attempts a `runas` relaunch before starting the interceptor. After bypassing
SmartScreen on a downloaded zip, approve the UAC prompt so WinDivert can open the
network interceptor. If administrator approval is denied, FlowBrake exits instead
of starting without the privileges needed for traffic limiting.

To create the release zip used by CI:

```powershell
.\scripts\package-windows.ps1
```

The package is written to `dist/FlowBrake-windows-x64-v<version>.zip` and
contains only the runtime payload:

- `FlowBrake.exe`
- `WinDivert.dll`
- `WinDivert64.sys`
- `README.md`
- `README.zh-CN.md`
- `LICENSE`

## CI/CD

GitHub Actions builds and packages Windows x64 only. The workflow runs
formatting, translation checks, tests, and clippy on
pushes to `main`, pull requests, and manual dispatches. Tags matching `v*` also
build the release executable, package it, and attach the zip and its SHA-256
checksum to the GitHub Release.

The repository does not currently define an MSI or installer-exe project. A
real installer can be added later with WiX, NSIS, or Inno Setup, but that needs
explicit install, upgrade, uninstall, elevation, and signing decisions. Until
then, the supported release artifact is the clean zip package.

## Running

Build the executable and run:

```powershell
cargo run -p flowbrake-ui
```

Or use the release build:

```powershell
.\target\release\flowbrake-ui.exe
```

Approve the UAC prompt when FlowBrake asks for administrator access.

Use the UI as follows:

1. The interceptor starts automatically after administrator approval.
2. Enter a speed value for a process or the global row.
3. Enable the corresponding download or upload checkbox to apply the limit.
4. Use `Block` to prevent new external connections and drop matching external traffic for a row.
5. Use `Adaptive` to make the limiter adjust toward the displayed target.
6. Click a row to open the detail sidebar and edit limits or inspect connections.
7. Double-click a grouped row to expand or collapse its per-PID children.
8. Open Settings from the title bar to choose language, switch speed units, or toggle IPv6 support.
9. Close the window while running to keep the app in the system tray.

Typing a limit value alone stores it as a draft. A limit only becomes active
when its checkbox is enabled.

`Block` combines socket-level blocking of new connection/accept operations with
packet-level blocking of existing traffic, including empty TCP control packets.
Global Block drops external IPv4/IPv6 packets before parsing, including ICMP,
regardless of the IPv6 statistics/limiting setting. Local loopback traffic is
preserved. This does not disable adapters or change Windows' link status; existing
TCP connections may remain listed until they time out.

Per-process packet blocking uses the endpoint-to-PID table, refreshing it when
Block changes or an unknown port is encountered. Socket blocking avoids that
table's polling delay for new connections from already selected PIDs. Processes
newly joining a saved executable-name group are covered once the UI discovers
them. Existing traffic that cannot be parsed or attributed to a PID remains a
limitation of per-process packet blocking. A socket-filter installation failure
is reported as `Block protection degraded` in the status bar.

To verify driver-level TCP blocking, run this opt-in test from an administrator
PowerShell terminal. Set the endpoint to a reachable external IPv4 or IPv6 TCP
server. The test blocks only its own PID, checks loopback and connectivity
restoration, and removes its filters on exit:

```powershell
$env:FLOWBRAKE_TEST_ENDPOINT = "<external-IP>:<port>"
cargo test -p flowbrake-windows live_process_block -- --ignored --nocapture
```

## Packet Loss Simulation

Select the computer, a process group, or an individual PID and open its Details
sidebar. Set **Download loss %** and **Upload loss %** independently between 0
and 100, with up to two decimal places. Changes apply when you press Enter or
leave the input. Invalid input displays an error and leaves the active rule unchanged.

- A blank process value inherits the global value for that direction.
- An explicit `0` disables simulated loss for that process, even when global loss is enabled.
- A blank or `0` global value disables global simulation.
- Process values replace global values; they are not sampled twice.
- Simulation covers parsed external TCP/UDP packets, including empty TCP control
  packets and retransmissions, for both IPv4 and IPv6. Loopback is preserved.
- `100` creates a packet blackhole; it does not install Socket Block filters.
  Connection attempts can remain pending until timeout.

The order is Block, simulated loss, then speed limiting. Simulated drops do not
consume token-bucket budget. The status bar separates packet drops caused by
Block, Loss, and Limit. The displayed loss percentage is the cumulative ratio of
simulated drops to packets sampled by active nonzero loss rules since the engine
started. Only simulated drops enter the numerator; sampled packets later dropped
by speed limiting remain in the denominator. Blocked packets, loopback, and
explicit 0% overrides are not sampled.
Random loss converges toward the configured percentage over many packets, so
short runs may differ. Combining loss with a speed limit can increase total drops.

Per-process simulation shares the endpoint-to-PID attribution limitations of
per-process blocking. Unattributed packets use the global loss setting. Packets
the TCP/UDP parser does not support pass without simulated loss. IPv6 simulation
is independent of the IPv6 statistics/limiting setting. Adaptive limiting uses
post-loss throughput; disable Adaptive when testing loss alone.

Global and executable-name group loss rules are saved with existing settings.
Individual PID overrides last for the current session, like PID speed limits.

## Settings and Persistence

Choose **Follow system / 简体中文 / English** in Settings. Language changes apply
immediately, including the tray menu, and preserve active rules and draft inputs.
The default is Follow system: `zh-CN`, `zh-SG`, and explicit `zh-Hans` locales use
Simplified Chinese; English and unsupported locales use English. Traditional
Chinese locales (`zh-TW`, `zh-HK`, `zh-MO`, and `zh-Hant`) fall back to English.
Follow system is resolved at startup and when selected; restart or select it again
after changing the Windows language.

Translations are embedded in the executable and work offline. Windows UAC and
SmartScreen follow the Windows language; original system error details may also
retain their system language. Language does not change numeric input rules:
use `.` as the decimal separator. Standard `KB/s` uses 1024 bytes per unit,
while ISP `Kb/s` uses 1000 bits per unit; internal speed limits are rounded to
whole KiB/s.

FlowBrake stores settings in:

```text
%APPDATA%\FlowBrake\settings.ini
```

The file is a simple `key=value` format and persists:

- Speed unit preference (`ISP units` / `Standard units`)
- Language preference (`language=system|zh-CN|en`; missing or invalid values use system)
- IPv6 support on/off
- Window size, position, and maximized state
- Expanded process groups
- Global limit, block, and adaptive settings
- Per-process rules keyed by executable name
- Download/upload simulated packet-loss overrides, including explicit 0% values

Rules are restored when matching processes appear again. Settings are saved when
the window is closed, minimized to tray, or when relevant preferences change.

## How Limiting Works

FlowBrake uses a token bucket per direction. Packets that exceed the available
bucket budget are dropped, then TCP naturally retransmits and backs off.

Important details:

- Limiting is based on TCP/UDP payload bytes, not full IP packet size.
- Empty TCP control packets, such as pure ACKs, do not consume rate budget.
- Speed counters track payload bytes that were actually allowed through.
- Global rules are evaluated before per-process rules.
- Internal limits are stored in KiB/s regardless of the displayed unit.

Because this is a drop-based limiter, very low limits can still cause TCP
timeouts or degraded connections. A delay/queue-based limiter would be more
connection-friendly, but is not implemented yet.

## Testing

Run the full validation suite:

```powershell
cargo fmt --all -- --check
.\scripts\check-translations.ps1
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run workspace tests from an elevated PowerShell on Windows: the UI test
executable inherits the application's administrator manifest. The live network
integration test additionally requires its documented endpoint and explicit opt-in.

## Translating

Translation resources live in `crates/flowbrake-ui/lang/`: the English POT
template and `zh-CN/LC_MESSAGES/flowbrake-ui.po`. Mark UI text with Slint `@tr(...)`;
put text generated by Rust in `crates/flowbrake-ui/ui/translations.slint` so it
uses the same catalog. Preserve placeholders, plural forms, protocol names,
process names, and units when translating. Startup elevation messages in
`src/i18n.rs` are a small, separately tested bilingual set used before the UI
exists; they are maintained separately from the PO catalog.

After changing source strings, update the POT and PO entries. Slint's official
translation extractor matching the project version is an optional way to
regenerate the POT; manual edits also work, and the checker verifies source/POT
and PO coverage. Run
`.\scripts\check-translations.ps1`, then build and check both languages in the
main window, Settings, Details, validation messages, and tray. Check the smallest
window and Windows display scaling for clipped text or missing glyphs. Adding a
language also requires registering its settings choice and system locale mapping;
a catalog alone does not make it selectable.

## WinDivert

FlowBrake depends on WinDivert for packet interception. The runtime files are
kept under `third_party/windivert/` so the Rust build does not depend on old
.NET publish output.

If you update WinDivert, replace both files together:

- `third_party/windivert/WinDivert.dll`
- `third_party/windivert/WinDivert64.sys`

Some antivirus products flag packet interception drivers. If that happens,
verify the WinDivert source and release you are using before adding an
exception.

## Limitations

- Windows-only
- Drop-based throttling can affect connection stability at very low limits
- TCP disconnect uses `SetTcpEntry` and supports IPv4 connections only; IPv6
  connections can be listed but not disconnected
- IPv6 interception can be disabled, but IPv4 is always intercepted when running
- No installer or signed driver distribution workflow yet

## License

FlowBrake is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
