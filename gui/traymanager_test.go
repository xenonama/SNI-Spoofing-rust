package main

import "testing"

func silentTrayLog(string, string) {}

// The manager must own a copy of the icon bytes so later caller-side
// mutation cannot corrupt the tray icon.
func TestTrayManagerCopiesIcon(t *testing.T) {
	src := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1}
	m := NewTrayManager(nil, nil, src, silentTrayLog)
	src[len(src)-1] = 99
	if m.icon[len(m.icon)-1] != 1 {
		t.Fatal("manager shares icon backing array with caller")
	}
	if !m.Enabled() {
		t.Fatal("default desired state should be enabled")
	}
	if m.IsActive() {
		t.Fatal("no instance exists yet, should be inactive")
	}
}

// Without an app (headless/unit context) Ensure must fail cleanly —
// no panic, no half-created instance — and Shutdown must stay safe.
func TestTrayManagerEnsureWithoutAppFailsCleanly(t *testing.T) {
	m := NewTrayManager(nil, nil, []byte{0x89, 'P', 'N', 'G'}, silentTrayLog)
	if err := m.Ensure(true); err == nil {
		t.Fatal("Ensure(true) without app should error")
	}
	if err := m.Ensure(false); err == nil {
		t.Fatal("Ensure(false) without app should error")
	}
	if m.IsActive() {
		t.Fatal("failed create must not report active")
	}
	m.Shutdown() // must not panic
}
