package pinentry

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var gnuPGAgentConfPINEntryProgramRx = regexp.MustCompile(`(?m)^\s*pinentry-program\s+(\S+)`)

// WithBinaryNameFromGnuPGAgentConf sets the name of the pinentry binary by
// reading ~/.gnupg/gpg-agent.conf, if it exists.
func WithBinaryNameFromGnuPGAgentConf() (clientOption ClientOption) {
	clientOption = func(*Client) {}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return clientOption
	}

	data, err := os.ReadFile(filepath.Join(userHomeDir, ".gnupg", "gpg-agent.conf"))
	if err != nil {
		return clientOption
	}

	match := gnuPGAgentConfPINEntryProgramRx.FindSubmatch(data)
	if match == nil {
		return clientOption
	}

	// FIXME add support for ~user and ~user/
	binaryName := string(match[1])
	switch {
	case binaryName == "~":
		binaryName = userHomeDir
	case strings.HasPrefix(binaryName, "~/"):
		binaryName = userHomeDir + strings.TrimPrefix(binaryName, "~")
	}

	return func(c *Client) {
		c.binaryName = binaryName
	}
}

// WithGPGTTY sets the tty.
func WithGPGTTY() ClientOption {
	if runtime.GOOS == "windows" {
		return nil
	}
	gpgTTY, ok := os.LookupEnv("GPG_TTY")
	if !ok {
		return nil
	}
	return WithCommandf("OPTION %s=%s", OptionTTYName, gpgTTY)
}
