// Package config loads and validates the load balancer's JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
)

// AutoInterface asks Load to pick the interface that carries the default route.
const AutoInterface = "auto"

type Config struct {
	Interface string   `json:"interface"`
	Backends  []string `json:"backends"`

	// backendAddrs is the parsed form of Backends, filled in by Validate.
	backendAddrs []netip.Addr
}

// Load reads the file at path, validates it and resolves the interface.
//
// Validation happens before anything touches the kernel, so a bad config is
// reported in full and the process exits without having attached anything.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Unknown keys are rejected: a typo such as "backend" would otherwise be
	// silently ignored and surface later as "no backends defined".
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s:\n%w", path, err)
	}

	if cfg.Interface == "" || cfg.Interface == AutoInterface {
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
		cfg.Interface = iface
	} else if _, err := net.InterfaceByName(cfg.Interface); err != nil {
		return nil, fmt.Errorf("interface %q: %w", cfg.Interface, err)
	}

	return &cfg, nil
}

// Validate checks the backend list and reports every problem at once, so the
// operator fixes the file in one pass instead of one error per run.
func (c *Config) Validate() error {
	var errs []error

	if len(c.Backends) == 0 {
		errs = append(errs, errors.New("  backends: at least one backend is required"))
	}

	addrs := make([]netip.Addr, 0, len(c.Backends))
	seen := make(map[netip.Addr]int, len(c.Backends))
	for i, s := range c.Backends {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q is not an IP address", i, s))
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q is not IPv4 (IPv6 is not supported yet)", i, s))
			continue
		}
		if first, dup := seen[addr]; dup {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q duplicates backends[%d]", i, s, first))
			continue
		}
		seen[addr] = i
		addrs = append(addrs, addr)
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}
	c.backendAddrs = addrs
	return nil
}

// BackendAddrs returns the validated backend addresses in config order.
func (c *Config) BackendAddrs() []netip.Addr {
	return c.backendAddrs
}

// getDefaultInterface returns the interface the kernel would use to reach the
// internet. Dialing UDP sends no packet; it only asks the routing table which
// local address would be used, and we map that address back to an interface.
func getDefaultInterface() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.Equal(localAddr.IP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no active interface found")
}
