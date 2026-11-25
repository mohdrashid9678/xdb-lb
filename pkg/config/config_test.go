package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		want     []string
		wantErrs []string
	}{
		{
			name: "valid",
			json: `{"interface":"eth0","backends":["10.0.0.1","10.0.0.2"]}`,
			want: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name: "ipv4-mapped ipv6 is unmapped",
			json: `{"backends":["::ffff:10.0.0.1"]}`,
			want: []string{"10.0.0.1"},
		},
		{
			name:     "no backends",
			json:     `{"interface":"eth0"}`,
			wantErrs: []string{"at least one backend"},
		},
		{
			name:     "unknown key",
			json:     `{"backend":["10.0.0.1"]}`,
			wantErrs: []string{`unknown field "backend"`},
		},
		{
			name:     "malformed json",
			json:     `{"backends":`,
			wantErrs: []string{"parse"},
		},
		{
			name: "every invalid backend is reported",
			json: `{"backends":["10.0.0.1","bad","10.0.0.1","fe80::1"]}`,
			wantErrs: []string{
				`backends[1]: "bad" is not an IP address`,
				`backends[2]: "10.0.0.1" duplicates backends[0]`,
				`backends[3]: "fe80::1" is not IPv4`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.json))
			if len(tt.wantErrs) > 0 {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				for _, want := range tt.wantErrs {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not mention %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.Backends) != len(tt.want) {
				t.Fatalf("got %d backends, want %d", len(cfg.Backends), len(tt.want))
			}
			for i, want := range tt.want {
				if cfg.Backends[i] != netip.MustParseAddr(want) {
					t.Errorf("backends[%d] = %v, want %s", i, cfg.Backends[i], want)
				}
			}
		})
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

	t.Run("explicit interface", func(t *testing.T) {
		cfg, err := Load(write(t, `{"interface":"lo","backends":["10.0.0.1"]}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Interface != "lo" {
			t.Fatalf("interface = %q, want lo", cfg.Interface)
		}
	})

	t.Run("unknown interface", func(t *testing.T) {
		_, err := Load(write(t, `{"interface":"nope0","backends":["10.0.0.1"]}`))
		if err == nil || !strings.Contains(err.Error(), "nope0") {
			t.Fatalf("expected an interface error, got %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})
}
