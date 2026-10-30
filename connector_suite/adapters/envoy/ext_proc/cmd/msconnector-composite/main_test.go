package main

import (
	"errors"
	"strings"
	"testing"
)

func TestShutdownResultPrioritizesCoordinatorFault(t *testing.T) {
	coordinatorErr := errors.New("event queue saturated")
	got := shutdownResult(errors.New("serve"), coordinatorErr, errors.New("observer"), errors.New("observer close"), errors.New("engine close"))
	if !errors.Is(got, coordinatorErr) || !strings.Contains(got.Error(), "coordinator failed") {
		t.Fatalf("shutdown result = %v", got)
	}
}

func TestValidateLoopbackAddressRequiresNumericLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18081", "[::1]:18081"} {
		if err := validateLoopbackAddress(address); err != nil {
			t.Fatalf("validateLoopbackAddress(%q): %v", address, err)
		}
	}
	for _, address := range []string{"localhost:18081", "0.0.0.0:18081", "example.test:18081", "127.0.0.1"} {
		if err := validateLoopbackAddress(address); err == nil {
			t.Fatalf("validateLoopbackAddress(%q) unexpectedly allowed", address)
		}
	}
}
