package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/twpayne/go-pinentry/v3"
)

func run() error {
	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithDesc("My multiline\ndescription"),
		pinentry.WithGPGTTY(),
		pinentry.WithPrompt("My prompt:"),
		pinentry.WithQualityBar(func(s string) (int, bool) {
			quality := 5 * len(s)
			if len(s) < 5 {
				quality = -quality
			}
			return quality, true
		}),
		pinentry.WithTitle("My title"),
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.Close(); err != nil {
			slog.Error("close", "err", err)
		}
	}()

	switch pin, fromCache, err := client.GetPIN(); {
	case pinentry.IsCancelled(err):
		fmt.Println("Cancelled")
		return err
	case err != nil:
		return err
	case fromCache:
		fmt.Printf("PIN: %s (from cache)\n", pin)
	default:
		fmt.Printf("PIN: %s\n", pin)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
