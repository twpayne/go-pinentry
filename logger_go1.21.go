//go:build go1.21

package pinentry

import "log/slog"

type Logger = slog.Logger

// DefaultLogger returns the default logger. It only exists for backwards
// compatibility with Go 1.20 and will be removed when Go 1.22 is released.
func DefaultLogger() *Logger {
	return slog.Default()
}
