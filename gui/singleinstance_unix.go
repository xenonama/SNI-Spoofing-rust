//go:build !windows

package main

// FIX(G1): on non-Windows dev builds there is no second-instance problem
// (releases target Windows); the Rust per-port mutex remains the guard.
func ensureSingleInstance() error { return nil }
