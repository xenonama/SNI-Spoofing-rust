<!-- ===== FILE: README.md ===== -->
# SNI Spoofer (Rust + Wails v3)

A fast, lightweight SNI-spoofing relay that bypasses DPI (Deep Packet
Inspection) by injecting a fake TLS ClientHello with a decoy SNI. This
is a full Rust rewrite of the original Python project by **Patterniha**,
with a modern React + Tailwind GUI running on Wails v3.

## About

The project relays TCP traffic to remote endpoints while spoofing the
SNI field in the TLS handshake. Nine different bypass methods are
supported, from simple wrong-sequence injection to advanced
split/fragmented/host-fake techniques. The GUI provides live metrics,
a console with filtering, and Smart Tools for probing endpoints and SNIs.

Original project (Python): [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

## Features

- Nine DPI bypass methods: `wrong_seq`, `wrong_seq_ttl`, `split_seq`,
  `fragmented`, `padding`, `delayed_retry`, `double_sni`, `hostfakesplit`,
  `fakedsplit`
- Automatic rotation (`auto` mode) — one method per connection
- TLS fingerprint profiles: legacy, Chrome 120/124, Firefox 122/124
- QUIC handling: `block`, `spoof`, `passthrough`
- Live metrics: active / total / OK / fail, per-session traffic
- Console with level filter, search, auto-scroll, export
- Smart Tools: rank endpoints, rank SNIs, pick fastest
- Config editor with atomic save
- Self-test suite (offline, no Admin required)
- Single-instance guard
- No coil whine, no Electron, ~12 MB binary

## Architecture

Data flow: React → Wails bindings → Go service → purego → Rust cdylib
→ WinDivert.

## Requirements

- Windows 10/11 (64-bit)
- [Rust](https://rustup.rs/) with the GNU toolchain
- [MinGW-w64](https://www.msys2.org/) (for linking)
- [Go 1.25+](https://go.dev/dl/)
- [Node.js 20+](https://nodejs.org/)
- [Wails v3 CLI](https://v3alpha.wails.io/): `go install github.com/wailsapp/wails/v3/cmd/wails3@latest`
- `WinDivert.dll` and `WinDivert64.sys` (see below)

## Building

```cmd
:: Rust engine
cd engine-ffi
cargo build --release

:: Frontend
cd ..\gui\frontend
npm install
npm run build

:: Wails app
cd ..
wails3 generate bindings -ts
go build -ldflags="-H windowsgui -s -w" -o build\bin\sni-gui.exe .

:: Copy the engine DLL next to the exe
copy ..\target\release\sni_engine.dll build\bin\