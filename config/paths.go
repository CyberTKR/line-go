package config

import (
	"os"
	"path/filepath"
	"strings"
)

const moduleName = "github.com/CyberTKR/line-go"

func defaultSessionPath() string {
	if value := os.Getenv("LINEGO_SESSION_PATH"); value != "" {
		return value
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return DefaultSessionPath
	}
	if resolved := findProjectSession(workingDirectory, DefaultSessionPath); resolved != "" {
		return resolved
	}
	return DefaultSessionPath
}

func findProjectSession(start, sessionPath string) string {
	if filepath.IsAbs(sessionPath) {
		return sessionPath
	}
	directory, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		moduleFile := filepath.Join(directory, "go.mod")
		if data, readErr := os.ReadFile(moduleFile); readErr == nil && strings.Contains(string(data), "module "+moduleName) {
			candidate := filepath.Join(directory, sessionPath)
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return candidate
			}
			return ""
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return ""
		}
		directory = parent
	}
}
