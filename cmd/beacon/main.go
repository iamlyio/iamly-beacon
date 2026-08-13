package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/reviam/beacon/internal/app"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	application, err := app.New(version)
	if err == nil {
		err = application.Execute(ctx, os.Args[1:])
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "beacon: %s\n", strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}
