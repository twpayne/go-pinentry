package main

import (
	"fmt"
	"os"

	"github.com/twpayne/go-pinentry/v2"
)

func run(logger *pinentry.Logger) error {
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
		pinentry.WithLogger(logger),
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.Close(); err != nil {
			logger.Error("close", "err", err)
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
	logger := pinentry.DefaultLogger()
	if err := run(logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
