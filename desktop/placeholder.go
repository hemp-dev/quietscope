//go:build !desktop
// +build !desktop

package main

// Stub main function to satisfy the compiler when building the desktop
// package without the 'desktop' build tag during Wails static analysis.
func main() {}
