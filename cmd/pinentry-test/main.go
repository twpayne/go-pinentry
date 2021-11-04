package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/twpayne/go-pinentry"
)

func run(logger *zerolog.Logger) error {
	client, err := pinentry.NewClient(
		pinentry.WithName("pinentry-mac"),
		pinentry.WithDesc("desc"),
		pinentry.WithOK("OK"),
		pinentry.WithQualityBar(func(s string) int {
			return 10*len(s) - 100
		}),
		pinentry.WithLogger(logger),
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.Close(); err != nil {
			logger.Err(err).Msg("close")
		}
	}()

	pin, fromCache, err := client.GetPIN()
	if err != nil {
		return err
	}

	if fromCache {
		fmt.Printf("%s (from cache)\n", pin)
	} else {
		fmt.Printf("%s\n", pin)
	}

	return nil
}

func main() {
	logger := log.Output(zerolog.NewConsoleWriter())
	if err := run(&logger); err != nil {
		logger.Err(err).Msg("error")
		os.Exit(1)
	}
}
