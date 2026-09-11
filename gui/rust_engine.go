// ===== FILE: gui/rust_engine.go =====
// Platform-agnostic Rust cdylib loader. The actual library-opening call
// is delegated to `openLibrary`, which has platform-specific implementations
// in rust_engine_windows.go and rust_engine_unix.go.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	libHandle uintptr
	loadErr   error
	once      sync.Once

	// Function pointers loaded from the Rust cdylib.
	fnStartEngine func(*byte) *byte
	fnStopEngine  func() *byte
	fnGetStats    func() *byte
	fnGetLogs     func() *byte
	fnClearLogs   func() *byte
	fnExportLogs  func() *byte
	fnRunProbeEP  func(*byte) *byte
	fnRunProbeSni func(*byte, *byte) *byte
	fnGetProbeRes func() *byte
	fnGetSniRes   func() *byte
	fnIsAdmin     func() byte
	fnIsRunning   func() byte
	fnFreeString  func(*byte)
	fnSelfTest    func(*byte) *byte
	fnSaveConfig  func(*byte) *byte
	fnLoadConfig  func() *byte
	fnConfigPath  func() *byte
	// FIX(WP0.2C/U5/B4): symbols for seeded defaults, active-connections
	// view and cooperative probe cancellation.
	fnGetDefaultConfig func() *byte
	fnGetActiveConns   func() *byte
	fnCancelProbe      func()

	configPathOverride string
	configPathMu       sync.RWMutex
)

func setConfigPathOverride(p string) {
	configPathMu.Lock()
	defer configPathMu.Unlock()
	configPathOverride = p
}

func resolvedConfigPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	configPathMu.RLock()
	defer configPathMu.RUnlock()
	if configPathOverride != "" {
		return configPathOverride
	}
	return filepath.Join(exeDir(), "config.json")
}

func loadLib() error {
	once.Do(func() {
		// FIX(B7): the cdylib is resolved from exeDir(), never CWD, so a
		// stray DLL in the working directory cannot be picked up.
		libPath := filepath.Join(exeDir(), "sni_engine.dll")

		if _, statErr := os.Stat(libPath); os.IsNotExist(statErr) {
			loadErr = fmt.Errorf("sni_engine.dll not found at %s", libPath)
			return
		}

		// Platform-specific open: syscall.LoadLibrary on Windows,
		// purego.Dlopen on Linux/macOS. See rust_engine_windows.go
		// and rust_engine_unix.go.
		libHandle, loadErr = openLibrary(libPath)
		if loadErr != nil {
			loadErr = fmt.Errorf("failed to load %s: %w", libPath, loadErr)
			return
		}

		// Register all FFI symbols. On failure we capture the error
		// instead of panicking so the GUI can show a friendly message.
		defer func() {
			if r := recover(); r != nil {
				loadErr = fmt.Errorf("failed to register FFI symbol: %v", r)
			}
		}()

		purego.RegisterLibFunc(&fnStartEngine, libHandle, "sni_start_engine")
		purego.RegisterLibFunc(&fnStopEngine, libHandle, "sni_stop_engine")
		purego.RegisterLibFunc(&fnGetStats, libHandle, "sni_get_stats")
		purego.RegisterLibFunc(&fnGetLogs, libHandle, "sni_get_logs")
		purego.RegisterLibFunc(&fnClearLogs, libHandle, "sni_clear_logs")
		purego.RegisterLibFunc(&fnExportLogs, libHandle, "sni_export_logs")
		purego.RegisterLibFunc(&fnRunProbeEP, libHandle, "sni_run_probe_endpoints")
		purego.RegisterLibFunc(&fnRunProbeSni, libHandle, "sni_run_probe_snis")
		purego.RegisterLibFunc(&fnGetProbeRes, libHandle, "sni_get_probe_results")
		purego.RegisterLibFunc(&fnGetSniRes, libHandle, "sni_get_sni_results")
		purego.RegisterLibFunc(&fnIsAdmin, libHandle, "sni_is_admin")
		purego.RegisterLibFunc(&fnIsRunning, libHandle, "sni_is_running")
		purego.RegisterLibFunc(&fnFreeString, libHandle, "sni_free_string")
		purego.RegisterLibFunc(&fnSelfTest, libHandle, "sni_self_test")
		purego.RegisterLibFunc(&fnSaveConfig, libHandle, "sni_save_config")
		purego.RegisterLibFunc(&fnLoadConfig, libHandle, "sni_load_config")
		purego.RegisterLibFunc(&fnConfigPath, libHandle, "sni_config_path")
		purego.RegisterLibFunc(&fnGetDefaultConfig, libHandle, "sni_get_default_config")
		purego.RegisterLibFunc(&fnGetActiveConns, libHandle, "sni_get_active_connections")
		purego.RegisterLibFunc(&fnCancelProbe, libHandle, "sni_cancel_probe")
	})
	return loadErr
}

func callString(fn func(*byte) *byte, arg string) (string, error) {
	if err := loadLib(); err != nil {
		return "", err
	}
	if fn == nil {
		return "", fmt.Errorf("rust function not loaded")
	}
	// Keep the argument alive for the duration of the call.
	cArg := append([]byte(arg), 0)
	ptr := fn(&cArg[0])
	if ptr == nil {
		return "", fmt.Errorf("rust returned nil")
	}
	defer fnFreeString(ptr)
	return goString(ptr), nil
}

func callNoArg(fn func() *byte) (string, error) {
	if err := loadLib(); err != nil {
		return "", err
	}
	if fn == nil {
		return "", fmt.Errorf("rust function not loaded")
	}
	ptr := fn()
	if ptr == nil {
		return "", fmt.Errorf("rust returned nil")
	}
	defer fnFreeString(ptr)
	return goString(ptr), nil
}

func goString(p *byte) string {
	if p == nil {
		return ""
	}
	var length int
	for ptr := uintptr(unsafe.Pointer(p)); *(*byte)(unsafe.Pointer(ptr)) != 0; ptr++ {
		length++
	}
	// Copy out of C memory before freeing.
	return string(unsafe.Slice(p, length))
}

func rustStartEngine(cfg string) (string, error)  { return callString(fnStartEngine, cfg) }
func rustStopEngine() (string, error)             { return callNoArg(fnStopEngine) }
func rustGetStats() (string, error)               { return callNoArg(fnGetStats) }
func rustGetLogs() (string, error)                { return callNoArg(fnGetLogs) }
func rustClearLogs() (string, error)              { return callNoArg(fnClearLogs) }
func rustExportLogs() (string, error)             { return callNoArg(fnExportLogs) }
func rustRunProbeEndpoints(eps string) (string, error) {
	return callString(fnRunProbeEP, eps)
}
func rustRunProbeSnis(snis, ep string) (string, error) {
	if err := loadLib(); err != nil {
		return "", err
	}
	if fnRunProbeSni == nil {
		return "", fmt.Errorf("rust function not loaded")
	}
	cSnis := append([]byte(snis), 0)
	cEp := append([]byte(ep), 0)
	ptr := fnRunProbeSni(&cSnis[0], &cEp[0])
	if ptr == nil {
		return "", fmt.Errorf("rust returned nil")
	}
	defer fnFreeString(ptr)
	return goString(ptr), nil
}
func rustGetProbeResults() (string, error) { return callNoArg(fnGetProbeRes) }
func rustGetSniResults() (string, error)   { return callNoArg(fnGetSniRes) }
func rustIsAdmin() bool {
	if err := loadLib(); err != nil {
		return false
	}
	if fnIsAdmin == nil {
		return false
	}
	return fnIsAdmin() != 0
}
// FIX(A3): backend liveness probe for the UI resync tick.
func rustIsEngineAlive() bool {
	if err := loadLib(); err != nil {
		return false
	}
	if fnIsRunning == nil {
		return false
	}
	return fnIsRunning() != 0
}
func rustSelfTest(configPath string) (string, error) {
	if configPath == "" {
		configPath = resolvedConfigPath("")
	}
	return callString(fnSelfTest, configPath)
}
func rustSaveConfig(cfg string) (string, error) { return callString(fnSaveConfig, cfg) }
func rustLoadConfig() (string, error)           { return callNoArg(fnLoadConfig) }

// FIX(WP0.2C): seeded first-launch defaults from ip_list.txt/sni_list.txt.
func rustGetDefaultConfig() (string, error) { return callNoArg(fnGetDefaultConfig) }

// IMPROVE(U5): live relay sessions for the Active Connections view.
func rustGetActiveConnections() (string, error) { return callNoArg(fnGetActiveConns) }

// FIX(B4): cooperative probe cancellation for window-close (T3).
func rustCancelProbe() {
	if err := loadLib(); err != nil {
		return
	}
	if fnCancelProbe == nil {
		return
	}
	fnCancelProbe()
}
func rustConfigPath() string {
	s, err := callNoArg(fnConfigPath)
	if err != nil {
		// Fall back to the local default so the UI always shows something.
		return toPathJSON(filepath.Join(exeDir(), "config.json"))
	}
	return s
}

func toPathJSON(p string) string {
	b, _ := json.Marshal(map[string]any{"ok": true, "path": p})
	return string(b)
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}