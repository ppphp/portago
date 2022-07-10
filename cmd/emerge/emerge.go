package main

import (
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/process"
	"os"
	"os/signal"
	"syscall"
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
	portage.DisableLegacyGlobals()
}

func main() {
	process.SanitizeFds()
	retval := emerge.EmergeMain(nil)
	os.Exit(retval)
}
