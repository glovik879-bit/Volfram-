package main

import (
	"bytes"
	"embed"
	"os"
	"path/filepath"
)

//go:embed rules/*.srs
var rulesFS embed.FS

func writeRules(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ents, err := rulesFS.ReadDir("rules")
	if err != nil {
		return err
	}
	for _, e := range ents {
		b, _ := rulesFS.ReadFile("rules/" + e.Name())
		p := filepath.Join(dir, e.Name())
		if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, b) {
			continue
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
