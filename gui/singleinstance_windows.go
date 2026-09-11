//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

var errAlreadyRunning = errors.New("another SNI Spoofer instance is already running")

var (
	modKernel32      = syscall.NewLazyDLL("kernel32.dll")
	modUser32        = syscall.NewLazyDLL("user32.dll")
	procCreateMutexW = modKernel32.NewProc("CreateMutexW")
	procMessageBoxW  = modUser32.NewProc("MessageBoxW")
)

// FIX(G1): app-level single-instance guard at launch (stdlib only — no new
// dependencies). The Rust per-port mutex only fires at engine Start; this
// stops a second GUI process outright with an explanatory dialog.
func ensureSingleInstance() error {
	const errorAlreadyExists = 183 // ERROR_ALREADY_EXISTS
	name, err := syscall.UTF16PtrFromString("SNI-Spoofer-App")
	if err != nil {
		return err
	}
	// lpMutexAttributes=NULL, bInitialOwner=FALSE.
	r1, _, lastErr := procCreateMutexW.Call(
		0,
		0,
		uintptr(unsafe.Pointer(name)),
	)
	if r1 == 0 {
		return lastErr
	}
	// Intentionally leaked: the mutex must live for the process lifetime.
	if errno, ok := lastErr.(syscall.Errno); ok && errno == errorAlreadyExists {
		msg, _ := syscall.UTF16PtrFromString("SNI Spoofer is already running.\n\nStop the other instance first.")
		title, _ := syscall.UTF16PtrFromString("SNI Spoofer")
		const mbIconInformation = 0x40
		_, _, _ = procMessageBoxW.Call(
			0,
			uintptr(unsafe.Pointer(msg)),
			uintptr(unsafe.Pointer(title)),
			mbIconInformation,
		)
		return errAlreadyRunning
	}
	return nil
}
