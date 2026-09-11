//go:build windows

package main

import (
    "syscall"
)

func openLibrary(path string) (uintptr, error) {
    handle, err := syscall.LoadLibrary(path)
    if err != nil {
        return 0, err
    }
    return uintptr(handle), nil
}