package pinentry

import (
	"os"
	"path/filepath"
	"regexp"
)

var gnuPGAgentConfPINEntryProgramRx = regexp.MustCompile(`(?m)^\s*pinentry-program\s+(\S+)`)

// WithBinaryNameFromGnuPGAgentConf sets the name of the pinentry binary by
// reading ~/.gnupg/gpg-agent.conf, if it exists.
func WithBinaryNameFromGnuPGAgentConf() (clientOption ClientOption) {
	clientOption = func(*Client) {}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	data, err := os.ReadFile(filepath.Join(userHomeDir, ".gnupg", "gpg-agent.conf"))
	if err != nil {
		return
	}

	match := gnuPGAgentConfPINEntryProgramRx.FindSubmatch(data)
	if match == nil {
		return
	}

	return func(c *Client) {
		c.binaryName = string(match[1])
	}
}
