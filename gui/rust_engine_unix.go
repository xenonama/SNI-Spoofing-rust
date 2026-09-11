//go:build !windows

package main

import (
    "github.com/ebitengine/purego"
)

func openLibrary(path string) (uintptr, error) {
    return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}