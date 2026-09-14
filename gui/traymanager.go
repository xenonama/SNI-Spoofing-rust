package main

// FIX(tray-icon): create-once + Show/Hide toggle.
//
// Root cause of "disable + enable loses the project icon": the old code
// implemented the toggle as destroy + SystemTray.New(). After app.Run(),
// Wails runs the native tray synchronously inside New(), reading the icon
// from bytes stored *before* New() returns — but SetIcon was only called
// *after* New(). So the re-created tray registered with the shell carrying
// an empty/fallback icon and the follow-up NIM_MODIFY did not reliably
// restore app.png. At startup the same sequence worked because New() only
// defers Run() there, so SetIcon seeded the PNG bytes before the native
// run() consumed them.
//
// New model: the tray instance (and its icon handle + shell registration)
// is created exactly once — always pre-Run from main.go, so the icon bytes
// are seeded on the known-good path — and enable/disable only flips
// visibility via Show()/Hide() (a single NIM_MODIFY, no re-registration,
// no PNG re-conversion). The icon therefore cannot go missing on toggle.

import (
	"fmt"
	"os"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// trayLogFunc is injectable for tests; defaults to app logger + stderr.
type trayLogFunc func(level, msg string)

// TrayManager owns the system tray instance and its window binding.
type TrayManager struct {
	mu     sync.Mutex
	gen    uint64
	tray   *application.SystemTray
	win    application.Window
	app    *application.App
	engine *EngineService

	// enabled is the desired visibility state. The tray instance is
	// created once and then only shown/hidden; IsActive reports
	// enabled && instance-exists so close-behavior (hide vs quit)
	// and the runtime probes keep working.
	enabled bool

	icon []byte

	log trayLogFunc
}

// NewTrayManager builds a manager. app/engine may be nil in tests.
func NewTrayManager(app *application.App, engine *EngineService, icon []byte, logFn trayLogFunc) *TrayManager {
	if logFn == nil {
		logFn = defaultTrayLog
	}
	cp := append([]byte(nil), icon...)
	return &TrayManager{app: app, engine: engine, icon: cp, enabled: true, log: logFn}
}

func defaultTrayLog(level, msg string) {
	if a := application.Get(); a != nil && a.Logger != nil {
		switch level {
		case "error":
			a.Logger.Error(msg)
		default:
			a.Logger.Info(msg)
		}
		return
	}
	// Pre-Run fallback so startup failures are never silent.
	fmt.Fprintln(os.Stderr, "tray["+level+"]:", msg)
}

// SetWindow stores the main window handle for click-to-restore.
// Called once after the window is created; never looked up dynamically
// again so Hide() cannot break it.
func (m *TrayManager) SetWindow(w application.Window) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.win = w
}

func (m *TrayManager) window() application.Window {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.win
}

// IsActive reports whether the tray is currently enabled and instantiated.
// Disabled-but-created counts as inactive so window-close behavior
// (hide-to-tray vs quit) follows the toggle, not mere existence.
func (m *TrayManager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tray != nil && m.enabled
}

// Enabled reports the desired visibility state (last Ensure argument).
func (m *TrayManager) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// Generation returns the lifecycle counter (for diagnostics).
func (m *TrayManager) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gen
}

// Ensure applies the desired visibility state. The native instance is
// created once (always pre-Run from main.go so the icon bytes are seeded
// before the native run consumes them); every later call only shows or
// hides that same instance, so the icon handle and shell registration are
// never torn down and cannot go missing on toggle. Fully serialized, so
// concurrent toggles cannot interleave.
func (m *TrayManager) Ensure(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.enabled = enabled
	if m.tray == nil {
		if err := m.createLocked(); err != nil {
			return err
		}
	}
	t := m.tray
	if t == nil {
		return fmt.Errorf("tray: create failed")
	}
	// Pre-Run these are harmless no-ops (no impl yet); main.go re-applies
	// Ensure on ApplicationStarted so a start-disabled tray is hidden once
	// its impl exists. Post-Run they InvokeSync to the live tray.
	if enabled {
		t.Show()
	} else {
		t.Hide()
	}
	return nil
}

func (m *TrayManager) createLocked() error {
	// Caller holds m.mu; only called when m.tray == nil, so there is no
	// stale instance to tear down and no destroy/create window at all.
	if m.app == nil {
		return fmt.Errorf("tray: app not ready")
	}

	icon := append([]byte(nil), m.icon...)
	if len(icon) == 0 {
		return fmt.Errorf("tray: empty icon bytes")
	}
	if !isPNG(icon) {
		m.log("error", fmt.Sprintf("tray: icon is %d bytes but not PNG; pushing anyway", len(icon)))
	}

	t := m.app.SystemTray.New()
	if t == nil {
		return fmt.Errorf("tray: SystemTray.New returned nil")
	}
	t.SetTooltip("SNI Spoofer")

	win := m.win
	t.OnClick(func() {
		// Runs on the native tray thread; Show/Focus are thread-safe
		// via InvokeSync inside Wails. Use the stored handle — never
		// currentWindow(), which is nil after Hide().
		if win == nil {
			win = m.window()
		}
		if win == nil {
			m.log("error", "tray: click with no window handle")
			return
		}
		win.Show()
		// Unminimise best-effort: Show restores hidden windows; if the
		// window was minimised, Show + Focus brings it back on Win32.
		win.Focus()
	})

	menu := m.app.NewMenu()
	eng := m.engine
	gen := m.gen + 1 // generation this instance will carry
	menu.Add("Start Engine").OnClick(func(ctx *application.Context) {
		if !m.stillCurrentGen(gen) {
			return
		}
		if eng == nil {
			return
		}
		// Never block the native tray thread on FFI.
		go func() {
			if err := eng.StartFromTray(); err != nil {
				m.log("error", "tray start failed: "+err.Error())
			}
		}()
	})
	menu.Add("Stop Engine").OnClick(func(ctx *application.Context) {
		if !m.stillCurrentGen(gen) {
			return
		}
		if eng == nil {
			return
		}
		go func() {
			if err := eng.StopFromTray(); err != nil {
				m.log("error", "tray stop failed: "+err.Error())
			}
		}()
	})
	menu.AddSeparator()
	appRef := m.app
	menu.Add("Exit").OnClick(func(ctx *application.Context) {
		if !m.stillCurrentGen(gen) {
			return
		}
		// Mark intent then quit; the cancelable safety timer lives
		// in main.go (requestQuit) so clean exits cancel it.
		quitting.Store(true)
		go func() {
			if appRef != nil {
				appRef.Quit()
			} else if a := application.Get(); a != nil {
				a.Quit()
			}
		}()
		armQuitSafetyNet()
	})
	t.SetMenu(menu)

	// Synchronous icon set. Production always creates pre-Run (from main.go),
	// where this only stores bytes for run() to consume — the native tray
	// is then built from app.png from the start, which is exactly why the
	// icon must be seeded here and never re-registered later. No retry
	// goroutine is needed and none is spawned.
	t.SetIcon(icon)

	m.tray = t
	m.gen = gen
	m.log("info", fmt.Sprintf("tray: created (gen=%d, icon=%d bytes)", m.gen, len(icon)))
	return nil
}

func (m *TrayManager) stillCurrentGen(gen uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tray != nil && m.gen == gen
}

func (m *TrayManager) destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyLocked()
	return nil
}

// destroyLocked hides then destroys; caller holds m.mu.
func (m *TrayManager) destroyLocked() {
	t := m.tray
	m.tray = nil
	m.gen++
	if t == nil {
		return
	}
	// Best-effort hide first so the shell removes the icon even if
	// Destroy races Explorer; Destroy removes map registration.
	func() {
		defer func() { _ = recover() }()
		t.Hide()
	}()
	func() {
		defer func() { _ = recover() }()
		t.Destroy()
	}()
	m.log("info", fmt.Sprintf("tray: destroyed (gen=%d)", m.gen))
}

// Shutdown is called on app exit: hide + destroy under lock.
func (m *TrayManager) Shutdown() {
	_ = m.destroy()
}

// isPNG reports whether b looks like a PNG (magic header).
func isPNG(b []byte) bool {
	return len(b) >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' &&
		b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A
}
