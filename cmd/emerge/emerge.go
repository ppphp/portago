package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/ppphp/portago/atom"
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
	atom.InternalCaller = true
	atom.DisableLegacyGlobals()
}

func main() {
	atom.SanitizeFds()

}
