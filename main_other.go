//go:build !windows && !volframandroid

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, data := appDirs()
	app := NewApp(cfg, data)
	u, err := app.Serve()
	if err != nil {
		panic(err)
	}
	if os.Getenv("VOLFRAM_TOKEN") != "" {
		app.token = os.Getenv("VOLFRAM_TOKEN")
		u = u[:len(u)-32] + app.token
	}
	app.StartBackground(false)
	fmt.Println(u)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	app.Shutdown()
}
