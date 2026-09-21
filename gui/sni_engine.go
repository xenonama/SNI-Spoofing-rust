package main

import (
	"context"
	"encoding/json"
	// FIX(titlebar): fmt for explicit window-lookup errors.
	"fmt"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// EngineService is the Wails v3 service exposed to the React frontend.
// Every method is a thin pass-through to the Rust cdylib (see rust_engine.go).
// Return values are JSON strings so the frontend parses once and stays
// in sync with the Rust Snapshot / probe schemas.
type EngineService struct {
	ctx context.Context
	// FIX(D1): serialize Start/Stop/Probe/Save against each other so
	// quick-succession clicks and Save-during-Start cannot interleave
	// Rust calls (the Rust side has its own START_STOP_MTX as well).
	mu sync.Mutex
}

// FIX(config-race): serialize every config.json write so two
// concurrent saves (frontend auto-save + tray toggle) cannot
// interleave and lose each other's changes.
var configWriteMu sync.Mutex

func NewEngineService() *EngineService {
	return &EngineService{}
}

func (s *EngineService) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	s.ctx = ctx
	return nil
}

func (s *EngineService) ServiceShutdown() error {
	// FIX(T3/B4): cancel any running probe first so it discards results
	// instead of publishing after the UI is gone, then stop the engine so
	// WinDivert handles are released — no zombie process, DLL unlocked.
	rustCancelProbe()
	_, _ = rustStopEngine()
	// FIX(tray-rewrite): remove the icon and cancel the quit safety net
	// on clean shutdown so Exit never hard-kills mid-save.
	cancelQuitSafetyNet()
	if m := getTrayManager(); m != nil {
		m.Shutdown()
	}
	return nil
}

// StartEngine is callable from the frontend as StartEngine(configJSON).
func (s *EngineService) StartEngine(configJSON string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rustStartEngine(configJSON)
}

func (s *EngineService) StopEngine() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rustStopEngine()
}

// FIX #9: tray-initiated engine start using the saved config.
func (s *EngineService) StartFromTray() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := rustLoadConfig()
	if err != nil {
		return err
	}
	_, err = rustStartEngine(cfg)
	return err
}

// FIX #9: tray-initiated engine stop.
func (s *EngineService) StopFromTray() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := rustStopEngine()
	return err
}

func (s *EngineService) GetStats() (string, error) {
	return rustGetStats()
}

func (s *EngineService) GetLogs() (string, error) {
	return rustGetLogs()
}

func (s *EngineService) ClearLogs() (string, error) {
	return rustClearLogs()
}

func (s *EngineService) ExportLogs() (string, error) {
	return rustExportLogs()
}

func (s *EngineService) RunProbeEndpoints(endpointsJSON string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := rustRunProbeEndpoints(endpointsJSON)
	if err == nil {
		s.EmitProbeResults()
	}
	return out, err
}

func (s *EngineService) RunProbeSnis(snisJSON, endpoint string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := rustRunProbeSnis(snisJSON, endpoint)
	if err == nil {
		s.EmitProbeResults()
	}
	return out, err
}

func (s *EngineService) GetProbeResults() (string, error) {
	return rustGetProbeResults()
}

func (s *EngineService) GetSniResults() (string, error) {
	return rustGetSniResults()
}

func (s *EngineService) IsAdmin() bool {
	return rustIsAdmin()
}

// FIX(A3): backend liveness probe for the UI resync tick.
func (s *EngineService) IsRunning() bool {
	return rustIsEngineAlive()
}

func (s *EngineService) SelfTest(configPath string) (string, error) {
	return rustSelfTest(configPath)
}

// EmitStats is called periodically by the frontend to poll stats.
// The frontend can also listen to a "stats" event if we push from Go.
func (s *EngineService) EmitStats() {
	statsJSON, _ := rustGetStats()
	application.Get().Event.Emit("stats", statsJSON)
}

// EmitLogs pushes new log lines to the frontend.
func (s *EngineService) EmitLogs() {
	logsJSON, _ := rustGetLogs()
	application.Get().Event.Emit("logs", logsJSON)
}

// EmitProbeResults pushes probe results to the frontend.
func (s *EngineService) EmitProbeResults() {
	prJSON, _ := rustGetProbeResults()
	srJSON, _ := rustGetSniResults()
	application.Get().Event.Emit("probe-results", prJSON)
	application.Get().Event.Emit("sni-results", srJSON)
}

// ConfigSave writes the config JSON to disk atomically.
// FIX(config-race): serialized under configWriteMu (then s.mu) so a
// frontend auto-save racing the tray toggle queues instead of
// interleaving writes and losing changes.
func (s *EngineService) ConfigSave(configJSON string) (string, error) {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return rustSaveConfig(configJSON)
}

// FIX(config-race): the frontend can poll this to make sure a
// save finished before the window closes.
func (s *EngineService) FlushConfig() error {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
	// Nothing to do here — acquiring the mutex guarantees that
	// any in-flight write has completed (mutex is held during
	// the write). If we reach this point, disk is in sync.
	return nil
}

// ConfigLoad reads the config JSON from disk.
func (s *EngineService) ConfigLoad() (string, error) {
	return rustLoadConfig()
}

// GetDefaultConfig returns the seeded first-launch defaults (WP0.2).
func (s *EngineService) GetDefaultConfig() (string, error) {
	return rustGetDefaultConfig()
}

// GetActiveConnections returns live relay sessions as a JSON array (U5).
func (s *EngineService) GetActiveConnections() (string, error) {
	return rustGetActiveConnections()
}

// CancelProbe cooperatively cancels a running probe (B4).
func (s *EngineService) CancelProbe() {
	rustCancelProbe()
}

// ConfigPath returns the path of config.json.
func (s *EngineService) ConfigPath() string {
	return rustConfigPath()
}

// selfTestOk reports whether a self-test report JSON contains ok:true.
func selfTestOk(report string) bool {
	var v struct {
		Ok bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(report), &v); err != nil {
		return false
	}
	return v.Ok
}

// FIX(tray-rewrite): stored main window handle. Set once from main.go
// after window creation; currentWindow() prefers it so Hide() can never
// break tray click-to-restore or title-bar controls.
var (
	mainWindowMu sync.RWMutex
	mainWindow   application.Window
)

// SetMainWindow stores the main window handle (called once from main).
func SetMainWindow(w application.Window) {
	mainWindowMu.Lock()
	defer mainWindowMu.Unlock()
	mainWindow = w
}

// FIX(titlebar): window controls with explicit error returns so
// the frontend cannot silently swallow failures.
func (s *EngineService) WindowMinimise() error {
	w := currentWindow()
	if w == nil {
		return fmt.Errorf("no window available")
	}
	w.Minimise()
	return nil
}

// FIX(titlebar): window controls with explicit error returns so
// the frontend cannot silently swallow failures.
func (s *EngineService) WindowToggleMaximise() error {
	w := currentWindow()
	if w == nil {
		return fmt.Errorf("no window available")
	}
	w.ToggleMaximise()
	return nil
}

// FIX(titlebar): window controls with explicit error returns so
// the frontend cannot silently swallow failures.
// FIX(config-persist): the frontend flushes config on
// beforeunload / visibilitychange before this runs.
// FIX(quit): the close-vs-quit decision is made in main.go's
// WindowClosing hook using the package-level `quitting` flag.
// This wrapper stays a thin forwarder.
func (s *EngineService) WindowClose() error {
	w := currentWindow()
	if w == nil {
		return fmt.Errorf("no window available")
	}
	w.Close()
	return nil
}

// FIX(titlebar): maximise-state probe for the React TitleBar icon.
func (s *EngineService) IsMaximised() bool {
	if w := currentWindow(); w != nil {
		return w.IsMaximised()
	}
	return false
}

// FIX(#1): canonical maximise-state probe for the manual-drag TitleBar.
func (s *EngineService) WindowIsMaximised() bool {
	if w := currentWindow(); w != nil {
		return w.IsMaximised()
	}
	return false
}

// FIX(#1): manual window drag for the frameless title bar. The Window
// interface exposes no exported drag method in beta.20 (startDrag is
// unexported), so this routes through the exported HandleMessage path
// ("wails:drag"), which the WebviewWindow handles natively.
// TODO(#1): if a future Wails beta exports a drag method, prefer it here.
func (s *EngineService) WindowStartDrag() error {
	w := currentWindow()
	if w == nil {
		return fmt.Errorf("no window available")
	}
	w.HandleMessage("wails:drag")
	return nil
}

// FIX(tray-rewrite): single manager reference. Wired once from main.go.
// All tray mutations go through TrayManager.Ensure (serialized,
// generation-guarded); there are no create/destroy callback pairs and
// no split locks anymore.
var (
	trayManagerMu sync.RWMutex
	trayManager   *TrayManager
)

// SetTrayManager wires the global manager (called once from main).
func SetTrayManager(m *TrayManager) {
	trayManagerMu.Lock()
	defer trayManagerMu.Unlock()
	trayManager = m
}

func getTrayManager() *TrayManager {
	trayManagerMu.RLock()
	defer trayManagerMu.RUnlock()
	return trayManager
}

// applyTrayState enables or disables the tray at runtime via the manager.
func applyTrayState(enabled bool) error {
	m := getTrayManager()
	if m == nil {
		return fmt.Errorf("tray manager not ready")
	}
	return m.Ensure(enabled)
}

// FIX(tray-rewrite): SetTrayEnabled — single writer for TRAY_ENABLED.
// Serialized under s.mu against ConfigSave/Start/Stop; persists via Rust
// then applies via TrayManager.Ensure. Strips the inert "ok" key from the
// load payload before re-saving so it never pollutes config.json.
// FIX(config-race): also serialized under configWriteMu (acquired before
// s.mu) so a tray write racing a frontend auto-save cannot interleave.
func (s *EngineService) SetTrayEnabled(enabled bool) error {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	trayLogInfo(fmt.Sprintf("SetTrayEnabled: start (target=%v)", enabled))
	raw, err := rustLoadConfig()
	if err != nil {
		trayLogInfo("SetTrayEnabled: disk config unreadable, seeding from defaults: " + err.Error())
		raw, err = rustGetDefaultConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	delete(cfg, "ok")
	cfg["TRAY_ENABLED"] = enabled
	// keep the legacy lowercase key in sync too
	cfg["tray_enabled"] = enabled

	out, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if _, err := rustSaveConfig(string(out)); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	trayLogInfo("SetTrayEnabled: config persisted")
	if err := applyTrayState(enabled); err != nil {
		return fmt.Errorf("apply tray state: %w", err)
	}
	trayLogInfo(fmt.Sprintf("SetTrayEnabled: applied (enabled=%v)", enabled))
	return nil
}

// FIX(tray-rewrite): split runtime vs persisted probes so the frontend
// can reconcile without flicker. TrayIsEnabled (legacy name) returns the
// runtime state; TrayPersistedEnabled returns the on-disk value.
func (s *EngineService) TrayIsEnabled() bool {
	return trayRuntimeEnabled()
}

// TrayRuntimeActive is the explicit runtime probe (tray exists right now).
func (s *EngineService) TrayRuntimeActive() bool {
	return trayRuntimeEnabled()
}

// TrayPersistedEnabled reads the on-disk TRAY_ENABLED value (tolerant
// coercion, defaults true). Used by Reload/Reset to re-apply only when
// disk and runtime disagree.
func (s *EngineService) TrayPersistedEnabled() bool {
	return readTrayEnabled()
}

// currentWindow prefers the stored main window handle (stable across
// Hide); falls back to beta.20 native accessors only if unset.
func currentWindow() application.Window {
	mainWindowMu.RLock()
	w := mainWindow
	mainWindowMu.RUnlock()
	if w != nil {
		return w
	}
	if m := getTrayManager(); m != nil {
		if ww := m.window(); ww != nil {
			return ww
		}
	}
	app := application.Get()
	if app == nil {
		return nil
	}
	if cw := app.Window.Current(); cw != nil {
		return cw
	}
	if ww, ok := app.Window.Get(""); ok {
		return ww
	}
	return nil
}
