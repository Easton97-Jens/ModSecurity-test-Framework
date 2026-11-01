//go:build !libmodsecurity

package main

import "testing"

func TestSourceOnlyBuildRefusesServingEngine(t *testing.T) {
	t.Parallel()
	if _, err := configuredEngine(""); err == nil {
		t.Fatal("source-only composite command unexpectedly exposed a serving engine")
	}
	if _, err := configuredEngine("/runtime.conf"); err == nil {
		t.Fatal("source-only composite command accepted a runtime configuration")
	}
}
