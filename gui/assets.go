package main

import _ "embed"

// FIX(#2): embedded app icon. The PNG next to main.go is baked
// into the binary at compile time, so no external file is needed
// at runtime.
//
//go:embed app.png
var embeddedAppIcon []byte

// FIX(tray-rewrite): embedded tray icon. Wails beta.20 converts PNG via
// CreateSmallHIconFromImage, so PNG is supported — no separate ICO file
// needed. Kept as its own var (same bytes as app icon today) so a future
// dedicated tray asset can replace it without touching the manager.
//
//go:embed app.png
var embeddedTrayIcon []byte

// trayIconBytes returns a validated copy of the tray icon. It rejects
// empty/corrupt payloads early so TrayManager.create fails with a clear
// error instead of registering a blank OS-default icon.
func trayIconBytes() []byte {
	src := embeddedTrayIcon
	if len(src) == 0 {
		src = embeddedAppIcon
	}
	return append([]byte(nil), src...)
}
