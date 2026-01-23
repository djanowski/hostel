package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
)

type ServiceConfig struct {
	Path string `toml:"path"`
}

type Config map[string]ServiceConfig

const (
	configDirName  = ".config/hostel"
	configFileName = "config.toml"
)

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, configDirName, configFileName), nil
}

func loadConfig() (Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	config := make(Config)

	if !fileExists(path) {
		return config, nil
	}

	_, err = toml.DecodeFile(path, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}

func saveConfig(config Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func isPortAvailable(port int) bool {
	// Check all possible bindings - localhost and all interfaces, IPv4 and IPv6
	addrs := []struct {
		network string
		address string
	}{
		{"tcp4", fmt.Sprintf("127.0.0.1:%d", port)},
		{"tcp4", fmt.Sprintf(":%d", port)},
		{"tcp6", fmt.Sprintf("[::1]:%d", port)},
		{"tcp6", fmt.Sprintf(":%d", port)},
	}

	for _, a := range addrs {
		ln, err := net.Listen(a.network, a.address)
		if err != nil {
			return false
		}
		ln.Close()
	}

	return true
}

func configToProjects(config Config) []Project {
	names := make([]string, 0, len(config))
	for name := range config {
		names = append(names, name)
	}
	sort.Strings(names)

	projects := make([]Project, 0, len(config))
	port := 8000

	for _, name := range names {
		for !isPortAvailable(port) {
			port++
		}
		projects = append(projects, Project{
			Name: name,
			Path: config[name].Path,
			Port: port,
		})
		port++
	}

	return projects
}

func validateConfig(config Config) error {
	for name, svc := range config {
		info, err := os.Stat(svc.Path)
		if os.IsNotExist(err) {
			return fmt.Errorf("service '%s': path does not exist: %s", name, svc.Path)
		}
		if err != nil {
			return fmt.Errorf("service '%s': cannot access path: %w", name, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("service '%s': path is not a directory: %s", name, svc.Path)
		}
	}
	return nil
}

func isValidServiceName(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
