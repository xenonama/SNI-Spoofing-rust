package main

import (
	"context"
	"encoding/json"
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
func (s *EngineService) ConfigSave(configJSON string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rustSaveConfig(configJSON)
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
