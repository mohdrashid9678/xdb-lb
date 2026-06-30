package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type Config struct {
	Interface string   `json:"interface"`
	Backends  []string `json:"backends"`
}

func Load(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Interface == "" || cfg.Interface == "auto" {
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
		cfg.Interface = iface
	}

	return &cfg, nil
}

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