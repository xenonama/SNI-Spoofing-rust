package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

// FIX(quit): set when the user explicitly asks to exit (Tray → Exit,
// X-with-tray-off). The WindowClosing hook checks this to decide between
// "hide to tray" and "actually close".
var quitting atomic.Bool

// FIX(tray-rewrite): single tray owner. Replaces the old split state
// (main.go pointer + sni_engine.go callbacks + trayMgrMu) which raced.
var trayMgr *TrayManager

// FIX(quit): cancelable safety net. The old code spawned an uncancelable
// `time.Sleep(2s); os.Exit(0)` on every Exit click, which could kill an
// in-flight atomic config save mid-rename. Now a single AfterFunc timer
// that clean shutdown cancels.
var (
	quitTimerMu sync.Mutex
	quitTimer   *time.Timer
)

func armQuitSafetyNet() {
	quitTimerMu.Lock()
	defer quitTimerMu.Unlock()
	if quitTimer != nil {
		quitTimer.Stop()
	}
	quitTimer = time.AfterFunc(2*time.Second, func() {
		os.Exit(0)
	})
}

func cancelQuitSafetyNet() {
	quitTimerMu.Lock()
	defer quitTimerMu.Unlock()
	if quitTimer != nil {
		quitTimer.Stop()
		quitTimer = nil
	}
}

// requestQuit marks intent, arms the safety net, and quits.
func requestQuit(app *application.App) {
	quitting.Store(true)
	armQuitSafetyNet()
	if app != nil {
		app.Quit()
	} else if a := application.Get(); a != nil {
		a.Quit()
	}
}

func main() {
	configPath := flag.String("config", "", "path to config.json")
	selfTest := flag.Bool("self-test", false, "run offline self-test and exit")
	flag.Parse()

	if *configPath != "" {
		setConfigPathOverride(*configPath)
		// FIX(tray-rewrite): sync override into Rust so save/load and the
		// tray gate read the same file (previously diverged).
		rustSetConfigPath(*configPath)
	}

	if *selfTest {
		report, err := rustSelfTest(resolvedConfigPath(*configPath))
		if err != nil {
			fmt.Fprintln(os.Stderr, "self-test failed to run:", err)
			os.Exit(1)
		}
		fmt.Println(report)
		if !selfTestOk(report) {
			os.Exit(1)
		}
		return
	}

	engine := NewEngineService()
	if err := ensureSingleInstance(); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(2)
	}
	app := application.New(application.Options{
		Name:        "SNI Spoofer",
		Description: "SNI spoofing injector + relay",
		Icon:        embeddedAppIcon,
		Services: []application.Service{
			application.NewService(engine),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	// FIX(tray-rewrite): manager owns lifecycle; window is created first
	// so click-to-restore captures a stable handle (never dynamically
	// looked up, which went nil after Hide()).
	trayMgr = NewTrayManager(app, engine, trayIconBytes(), nil)
	SetTrayManager(trayMgr)

	trayEnabled := readTrayEnabled()
	trayLogInfo(fmt.Sprintf("startup: readTrayEnabled=%v (tray_enabled from config.json)", trayEnabled))

	mainWindow := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:                      "SNI Spoofer",
		Width:                      1180,
		Height:                     780,
		MinWidth:                   900,
		MinHeight:                  620,
		DefaultContextMenuDisabled: true,
		Frameless:                  true,
	})
	trayMgr.SetWindow(mainWindow)
	// EngineService window controls also use the stored handle.
	SetMainWindow(mainWindow)

	// Create the tray BEFORE app.Run() in all cases. The instance (and its
	// icon) is created exactly once: pre-Run SetIcon seeds the PNG bytes
	// the native run() consumes, so the shell registration always carries
	// app.png. Toggling later only shows/hides this instance (see Ensure),
	// which is what keeps the project icon intact across disable/enable.
	if err := trayMgr.Ensure(trayEnabled); err != nil {
		fmt.Fprintln(os.Stderr, "tray create failed:", err)
		trayLogError("startup tray create failed: " + err.Error())
	} else {
		trayLogInfo(fmt.Sprintf("startup: tray created (enabled=%v)", trayEnabled))
	}
	// FIX(tray-icon): Show/Hide are no-ops before Run() (no impl yet), so
	// a start-disabled tray would still pop in visibly once its pending Run
	// executes. Re-apply the desired state once the app is up, plus one
	// delayed re-apply that reads the *current* state — the pending tray Run
	// is dispatched asynchronously, so this covers every ordering without
	// ever overriding a toggle the user made in the meantime.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		trayMgr.Ensure(trayMgr.Enabled())
		time.AfterFunc(500*time.Millisecond, func() {
			trayMgr.Ensure(trayMgr.Enabled())
		})
	})

	mainWindow.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		if quitting.Load() {
			return
		}
		if !trayRuntimeEnabled() {
			quitting.Store(true)
			return
		}
		event.Cancel()
		mainWindow.Hide()
	})
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
	// Clean exit: cancel the safety net and remove the icon.
	cancelQuitSafetyNet()
	if trayMgr != nil {
		trayMgr.Shutdown()
	}
}

// trayRuntimeEnabled reports whether a live tray exists right now.
func trayRuntimeEnabled() bool {
	if trayMgr == nil {
		return false
	}
	return trayMgr.IsActive()
}

func trayLogInfo(msg string) {
	if trayMgr != nil {
		trayMgr.log("info", msg)
		return
	}
	defaultTrayLog("info", msg)
}

func trayLogError(msg string) {
	if trayMgr != nil {
		trayMgr.log("error", msg)
		return
	}
	defaultTrayLog("error", msg)
}

// readTrayEnabled reads TRAY_ENABLED/tray_enabled with tolerant coercion
// (bool, "true/1/yes/on" strings, numbers). Defaults to true on any error.
func readTrayEnabled() bool {
	p := resolvedConfigPath("")
	data, err := os.ReadFile(p)
	if err != nil {
		return true
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		trayLogError("tray: config.json parse failed: " + err.Error())
		return true
	}
	v, ok := raw["TRAY_ENABLED"]
	if !ok {
		v, ok = raw["tray_enabled"]
	}
	if !ok {
		return true
	}
	return coerceTrayBool(v, true)
}

// coerceTrayBool interprets bool/string/number tray values.
func coerceTrayBool(v any, fallback bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		switch s {
		case "true", "1", "yes", "y", "on":
			return true
		case "false", "0", "no", "n", "off", "":
			return false
		default:
			return fallback
		}
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case uint64:
		return t != 0
	default:
		return fallback
	}
}
