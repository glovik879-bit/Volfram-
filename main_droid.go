//go:build volframandroid

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	setupResolver()
	cfg, data := appDirs()
	app := NewApp(cfg, data)
	if d := os.Getenv("VOLFRAM_LIBDIR"); d != "" {
		app.coreDir = d
	}
	app.rulesDir = filepath.Join(data, "rules")
	if t := os.Getenv("VOLFRAM_TOKEN"); t != "" {
		app.token = t
	}
	os.Unsetenv("VOLFRAM_TOKEN")
	os.Unsetenv("VOLFRAM_CTL")
	u, err := app.Serve()
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	app.onQuit = func() {
		app.Shutdown()
		_, _, _ = ctlCall(M{"cmd": "quit"}, 3*time.Second)
		os.Exit(0)
	}
	go ctlEvents(app)
	app.StartBackground(false)
	fmt.Println(u)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	app.Shutdown()
}
