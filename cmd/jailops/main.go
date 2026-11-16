// Command jailops is the JailOps command line client. It talks to a daemon
// through the SDK only; all behaviour lives in internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"jailops.net/jailops/internal/cli"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// a signal ends the context: a command stops, and exec and shell put the terminal back before they exit
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	env := cli.DefaultEnv()
	env.Version = version
	code := cli.Execute(ctx, env, os.Args[1:])
	stop()
	os.Exit(code)
}
