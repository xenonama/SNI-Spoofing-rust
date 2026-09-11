package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Preserve CLI behavior from the Slint build:
	//   --config <path>  override config.json location
	//   --self-test      offline check, print report, exit (0/1)
	configPath := flag.String("config", "", "path to config.json")
	selfTest := flag.Bool("self-test", false, "run offline self-test and exit")
	flag.Parse()

	if *configPath != "" {
		setConfigPathOverride(*configPath)
	}

	if *selfTest {
		report, err := rustSelfTest(resolvedConfigPath(*configPath))
		if err != nil {
			fmt.Fprintln(os.Stderr, "self-test failed to run:", err)
			os.Exit(1)
		}
		fmt.Println(report)
		// Exit 1 when the report says ok:false (mirrors Rust exit code).
		if !selfTestOk(report) {
			os.Exit(1)
		}
		return
	}

	engine := NewEngineService()
	// FIX(G1): refuse a second GUI process at launch (the Rust per-port
	// mutex additionally guards engine Start). Self-test stays exempt so
	// diagnostics can run alongside the app.
	if err := ensureSingleInstance(); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(2)
	}
	app := application.New(application.Options{
		Name:        "SNI Spoofer",
		Description: "SNI spoofing injector + relay",
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
	app.Window.NewWithOptions(application.WebviewWindowOptions{
 		Title:  "SNI Spoofer",
 		Width:  1180,
 		Height: 780,
 		MinWidth:  900,
 		MinHeight: 620,
	})
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
