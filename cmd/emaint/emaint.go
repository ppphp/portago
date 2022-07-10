package main

import (
	"github.com/ppphp/portago/pkg/portage/vars"
	"os"
	"os/signal"
	"syscall"

	"github.com/ppphp/portago/pkg/emaint"
)

func init() {
	signalHandler := func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		for {
			select {
			case sig := <-sigChan:
				switch sig {
				case syscall.SIGINT:
					os.Exit(128 + 2)
				case syscall.SIGTERM:
					os.Exit(128 + 9)
				}
			}
		}
	}
	go signalHandler()
	vars.InternalCaller = true
}

func main() {
	err := emaint.EmaintMain(os.Args[1:])
	if err != nil {
		if err == syscall.EACCES {
			print("\nemaint: Need superuser access\n")
		}
		os.Exit(1)
	}
}
