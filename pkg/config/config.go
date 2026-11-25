// Package config loads and validates the load balancer configuration.
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

const autoInterface = "auto"

type Config struct {
	Interface string
	Backends  []netip.Addr
}

type file struct {
	Interface string   `json:"interface"`
	Backends  []string `json:"backends"`
}

// Load reads the configuration at path and resolves the interface to attach to.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	cfg.Interface, err = resolveInterface(cfg.Interface)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// Parse decodes and validates a JSON configuration.
func Parse(raw []byte) (*Config, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	backends, err := parseBackends(f.Backends)
	if err != nil {
		return nil, fmt.Errorf("invalid backends:\n%w", err)
	}
	return &Config{Interface: f.Interface, Backends: backends}, nil
}

// parseBackends reports every invalid entry, not just the first.
func parseBackends(in []string) ([]netip.Addr, error) {
	if len(in) == 0 {
		return nil, errors.New("  at least one backend is required")
	}

	var errs []error
	addrs := make([]netip.Addr, 0, len(in))
	seen := make(map[netip.Addr]int, len(in))
	for i, s := range in {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q is not an IP address", i, s))
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q is not IPv4", i, s))
			continue
		}
		if first, dup := seen[addr]; dup {
			errs = append(errs, fmt.Errorf("  backends[%d]: %q duplicates backends[%d]", i, s, first))
			continue
		}
		seen[addr] = i
		addrs = append(addrs, addr)
	}
	return addrs, errors.Join(errs...)
}

func resolveInterface(name string) (string, error) {
	if name == "" || name == autoInterface {
		iface, err := defaultInterface()
		if err != nil {
			return "", fmt.Errorf("auto-detect interface: %w", err)
		}
		return iface, nil
	}
	if _, err := net.InterfaceByName(name); err != nil {
		return "", fmt.Errorf("interface %q: %w", name, err)
	}
	return name, nil
}

// defaultInterface returns the interface that carries the default route.
// Dialing UDP sends no packet; it only resolves the local address.
func defaultInterface() (string, error) {
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
	return "", errors.New("no active interface found")
}
