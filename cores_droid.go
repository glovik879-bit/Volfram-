//go:build volframandroid

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const SingboxVersion = "1.14.4"
const XrayVersion = "26.10.31"

func extractCores(coreDir, rulesDir string) error {
	if err := writeRules(rulesDir); err != nil {
		return err
	}
	for _, n := range []string{"sing-box", "xray", "tun2socks"} {
		p := filepath.Join(coreDir, exeName(n))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return fmt.Errorf("не найден компонент %s", exeName(n))
		}
	}
	return nil
}
