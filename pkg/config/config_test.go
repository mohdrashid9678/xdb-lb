package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		backends []string
		wantErrs []string // substrings that must all appear; empty means valid
	}{
		{name: "valid", backends: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "empty", backends: nil, wantErrs: []string{"at least one backend"}},
		{name: "not an IP", backends: []string{"10.0.0.1", "nope"}, wantErrs: []string{`backends[1]: "nope" is not an IP address`}},
		{name: "ipv6", backends: []string{"::1"}, wantErrs: []string{"is not IPv4"}},
		{name: "duplicate", backends: []string{"10.0.0.1", "10.0.0.1"}, wantErrs: []string{"duplicates backends[0]"}},
		{
			name:     "all problems reported together",
			backends: []string{"10.0.0.1", "bad", "10.0.0.1", "fe80::1"},
			wantErrs: []string{"backends[1]", "backends[2]", "backends[3]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Backends: tt.backends}
			err := cfg.Validate()
			if len(tt.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := len(cfg.BackendAddrs()); got != len(tt.backends) {
					t.Fatalf("BackendAddrs: got %d addresses, want %d", got, len(tt.backends))
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			for _, want := range tt.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestValidateUnmapsIPv4InIPv6(t *testing.T) {
	cfg := &Config{Backends: []string{"::ffff:10.0.0.1"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := cfg.BackendAddrs()[0], netip.MustParseAddr("10.0.0.1"); got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLoad(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("loopback", func(t *testing.T) {
		cfg, err := Load(write(t, `{"interface":"lo","backends":["10.0.0.1"]}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Interface != "lo" {
			t.Fatalf("interface: got %q, want lo", cfg.Interface)
		}
	})

	t.Run("unknown key is rejected", func(t *testing.T) {
		_, err := Load(write(t, `{"interface":"lo","backend":["10.0.0.1"]}`))
		if err == nil || !strings.Contains(err.Error(), "backend") {
			t.Fatalf("expected an unknown-field error, got %v", err)
		}
	})

	t.Run("missing interface is rejected", func(t *testing.T) {
		_, err := Load(write(t, `{"interface":"does-not-exist0","backends":["10.0.0.1"]}`))
		if err == nil || !strings.Contains(err.Error(), "does-not-exist0") {
			t.Fatalf("expected an interface error, got %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})
}
