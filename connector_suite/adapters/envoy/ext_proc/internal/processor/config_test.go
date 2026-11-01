package processor

import (
	"testing"
	"time"
)

func TestConfigRejectsNonLoopbackListenAddresses(t *testing.T) {
	base := Config{
		ListenAddress:        "127.0.0.1:18083",
		TransactionIDHeader:  "x-request-id",
		MaxHeaderCount:       128,
		MaxHeaderNameBytes:   256,
		MaxHeaderValueBytes:  8192,
		MaxTotalHeaderBytes:  32768,
		MaxBodyChunkBytes:    1048576,
		MaxGRPCMessageBytes:  1114112,
		EngineTimeoutMS:      150,
		StreamIdleTimeoutMS:  1000,
		StreamMaxLifetimeMS:  5000,
		MaxConcurrentStreams: 4,
		CleanupTimeoutMS:     1000,
		ShutdownTimeoutMS:    5000,
		LateActionPolicy:     LateActionSafe,
	}
	for _, address := range []string{"0.0.0.0:18083", ":18083", "192.0.2.10:18083", "localhost:18083", "[::]:18083"} {
		config := base
		config.ListenAddress = address
		if err := config.Validate(); err == nil {
			t.Errorf("Config.Validate() accepted non-loopback address %q", address)
		}
	}
}

func TestConfigAcceptsIPv4AndIPv6LoopbackListenAddresses(t *testing.T) {
	base := Config{
		TransactionIDHeader:  "x-request-id",
		MaxHeaderCount:       128,
		MaxHeaderNameBytes:   256,
		MaxHeaderValueBytes:  8192,
		MaxTotalHeaderBytes:  32768,
		MaxBodyChunkBytes:    1048576,
		MaxGRPCMessageBytes:  1114112,
		EngineTimeoutMS:      150,
		StreamIdleTimeoutMS:  1000,
		StreamMaxLifetimeMS:  5000,
		MaxConcurrentStreams: 4,
		CleanupTimeoutMS:     1000,
		ShutdownTimeoutMS:    5000,
		LateActionPolicy:     LateActionSafe,
	}
	for _, address := range []string{"127.0.0.1:18083", "127.255.255.254:18083", "[::1]:18083"} {
		config := base
		config.ListenAddress = address
		if err := config.Validate(); err != nil {
			t.Errorf("Config.Validate() rejected loopback address %q: %v", address, err)
		}
	}
}

func TestConfigRejectsTimeoutMillisecondOverflow(t *testing.T) {
	maxNativeInt := int64(^uint(0) >> 1)
	if maxNativeInt < maxTimeoutMS+1 {
		t.Skip("native int cannot represent timeout overflow boundary")
	}
	limit := int64(maxTimeoutMS)
	base := Config{
		ListenAddress:        "127.0.0.1:18083",
		TransactionIDHeader:  "x-request-id",
		MaxHeaderCount:       128,
		MaxHeaderNameBytes:   256,
		MaxHeaderValueBytes:  8192,
		MaxTotalHeaderBytes:  32768,
		MaxBodyChunkBytes:    1048576,
		MaxGRPCMessageBytes:  1114112,
		EngineTimeoutMS:      150,
		StreamIdleTimeoutMS:  1000,
		StreamMaxLifetimeMS:  5000,
		MaxConcurrentStreams: 4,
		CleanupTimeoutMS:     1000,
		ShutdownTimeoutMS:    5000,
		LateActionPolicy:     LateActionSafe,
	}
	tests := []struct {
		name  string
		set   func(*Config, int)
		value int
		valid bool
	}{
		{"engine just below maximum", func(c *Config, v int) { c.EngineTimeoutMS = v }, int(limit - 1), true},
		{"engine at maximum", func(c *Config, v int) { c.EngineTimeoutMS = v }, int(limit), true},
		{"engine above maximum", func(c *Config, v int) { c.EngineTimeoutMS = v }, int(limit + 1), false},
		{"cleanup just below maximum", func(c *Config, v int) { c.CleanupTimeoutMS = v }, int(limit - 1), true},
		{"cleanup at maximum", func(c *Config, v int) { c.CleanupTimeoutMS = v }, int(limit), true},
		{"cleanup above maximum", func(c *Config, v int) { c.CleanupTimeoutMS = v }, int(limit + 1), false},
		{"shutdown just below maximum", func(c *Config, v int) { c.ShutdownTimeoutMS = v }, int(limit - 1), true},
		{"shutdown at maximum", func(c *Config, v int) { c.ShutdownTimeoutMS = v }, int(limit), true},
		{"shutdown above maximum", func(c *Config, v int) { c.ShutdownTimeoutMS = v }, int(limit + 1), false},
		{"stream lifetime at maximum", func(c *Config, v int) { c.StreamMaxLifetimeMS = v }, int(limit), true},
		{"stream lifetime above maximum", func(c *Config, v int) { c.StreamMaxLifetimeMS = v }, int(limit + 1), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.set(&config, test.value)
			err := config.Validate()
			if test.valid && err != nil {
				t.Fatalf("Config.Validate() rejected boundary value: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatalf("Config.Validate() accepted overflowing timeout value %d", test.value)
			}
		})
	}
}

func TestConfigTimeoutsConvertWithoutOverflow(t *testing.T) {
	config := Config{EngineTimeoutMS: 150, CleanupTimeoutMS: 1000, ShutdownTimeoutMS: 5000}
	if got, want := config.engineTimeout(), 150*time.Millisecond; got != want {
		t.Fatalf("engineTimeout() = %s, want %s", got, want)
	}
	if got, want := config.cleanupTimeout(), time.Second; got != want {
		t.Fatalf("cleanupTimeout() = %s, want %s", got, want)
	}
	if got, want := config.shutdownTimeout(), 5*time.Second; got != want {
		t.Fatalf("shutdownTimeout() = %s, want %s", got, want)
	}
	if int64(^uint(0)>>1) >= maxTimeoutMS {
		limit := int64(maxTimeoutMS)
		if got := (Config{EngineTimeoutMS: int(limit)}).engineTimeout(); got <= 0 {
			t.Fatalf("maximum engine timeout converted to non-positive duration: %s", got)
		}
	}
}
