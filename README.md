# FlowBrake

![FlowBrake app icon](assets/app-icon.png)

FlowBrake is a lightweight Windows network limiter written in Rust. It uses
WinDivert to intercept IPv4 TCP/UDP traffic, maps packets back to owning
processes with the Windows IP Helper API, and provides a Slint-based desktop UI
for per-process and global throttling.

This repository contains the Rust rewrite only. The earlier C# / WinForms
implementation and generated .NET publish artifacts have been removed.

## Features

- Per-process download and upload limits in KB/s
- Global download and upload limits for all traffic
- Process grouping by executable name, with optional per-PID expansion
- Block-all switches for global or per-process traffic
- TCP connection list in the sidebar with per-connection and bulk disconnect (IPv4)
- Adaptive mode that adjusts token-bucket rates toward the configured target
- Live rolling speed display
- System tray support while the interceptor is running
- Windows GUI executable with embedded icon and application manifest

## Platform Support

FlowBrake is Windows-only.

Requirements:

- Windows 10/11 x64
- Administrator privileges at runtime
- Rust stable toolchain with the MSVC target
- Visual Studio Build Tools / Windows SDK, including `link.exe` and `rc.exe`

The application currently handles IPv4 TCP/UDP traffic. IPv6 packets are passed
through unchanged.

## Repository Layout

```text
crates/flowbrake-core/      Shared rules, token bucket, formatting, grouping
crates/flowbrake-windows/   WinDivert, IP Helper, packet parsing, engine loop
crates/flowbrake-ui/        Slint UI, tray integration, app state
assets/                     Compile-time application resources
third_party/windivert/        Runtime WinDivert DLL and driver files
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
prompt when the app is launched. After bypassing SmartScreen on a downloaded
zip, approve the UAC prompt so WinDivert can open the network interceptor. If
administrator approval is denied, FlowBrake exits instead of starting without
the privileges needed for traffic limiting.

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
- `LICENSE`

## CI/CD

GitHub Actions builds and packages Windows x64 only. The workflow runs
formatting, tests, clippy, a release build, and the clean zip packaging step on
pushes to `main`, pull requests, and manual dispatches. Tags matching `v*` also
attach the zip and its SHA-256 checksum to the GitHub Release.

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
4. Use `Block` to drop all matching traffic for a row.
5. Use `Adaptive` to make the limiter adjust toward the displayed target.
6. Close the window while running to keep the app in the system tray.

Typing a limit value alone stores it as a draft. A limit only becomes active
when its checkbox is enabled.

## How Limiting Works

FlowBrake uses a token bucket per direction. Packets that exceed the available
bucket budget are dropped, then TCP naturally retransmits and backs off.

Important details:

- Limiting is based on TCP/UDP payload bytes, not full IP packet size.
- Empty TCP control packets, such as pure ACKs, do not consume rate budget.
- Speed counters track payload bytes that were actually allowed through.
- Global rules are evaluated before per-process rules.

Because this is a drop-based limiter, very low limits can still cause TCP
timeouts or degraded connections. A delay/queue-based limiter would be more
connection-friendly, but is not implemented yet.

## Testing

Run the full validation suite:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

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
- IPv4 only
- Drop-based throttling can affect connection stability at very low limits
- TCP disconnect uses `SetTcpEntry` and currently supports IPv4 connections only
- No persistent configuration file yet
- No installer or signed driver distribution workflow yet

## License

FlowBrake is licensed under the MIT License. See [LICENSE](LICENSE).
