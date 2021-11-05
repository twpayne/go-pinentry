// Package pinentry provides a client to GnuPG's pinentry.
//
// See info pinentry.
// See https://www.gnupg.org/related_software/pinentry/index.html.
// See https://www.gnupg.org/documentation/manuals/assuan.pdf.
package pinentry

// FIXME add secure logging mode to avoid logging PIN
// FIXME add some unit tests
// FIXME add explicit ErrCancelled error (code 83886179)

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/multierr"
)

// Options.
const (
	OptionAllowExternalPasswordCache = "allow-external-password-cache"
	OptionDefaultOK                  = "default-ok"
	OptionDefaultCancel              = "default-cancel"
	OptionDefaultPrompt              = "default-prompt"
	OptionTTYName                    = "ttyname"
	OptionTTYType                    = "ttytype"
	OptionLCCType                    = "lc-ctype"
)

// An AssuanError is returned when an error is sent over the Assuan protocol.
type AssuanError struct {
	Code        int
	Description string
}

func (e *AssuanError) Error() string {
	return e.Description
}

// An UnexpectedResponseError is returned when an unexpected response is
// recieved.
type UnexpectedResponseError struct {
	line []byte
}

func newUnexpectedResponseError(line []byte) UnexpectedResponseError {
	return UnexpectedResponseError{
		line: line,
	}
}

func (e UnexpectedResponseError) Error() string {
	return fmt.Sprintf("pinentry: unexpected response: %q", e.line)
}

var errorRx = regexp.MustCompile(`\AERR (\d+) (.*)\z`)

// A QualityFunc evaluates the quality of a password. It should return a value
// between -100 and 100. The absolute value of the return value is used as the
// quality. Negative values turn the quality bar red. The boolean return value
// indicates whether the quality is valid.
type QualityFunc func(string) (int, bool)

// A Client is a pinentry client.
type Client struct {
	binaryName  string
	args        []string
	commands    []string
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      *bufio.Reader
	qualityFunc QualityFunc
	logger      *zerolog.Logger
}

// A ClientOption sets an option on a Client.
type ClientOption func(*Client)

// WithArgs appends extra arguments to the pinentry command.
func WithArgs(args []string) ClientOption {
	return func(c *Client) {
		c.args = append(c.args, args...)
	}
}

// WithBinaryName sets the name of the pinentry binary name. The default is
// pinentry.
func WithBinaryName(binaryName string) ClientOption {
	return func(c *Client) {
		c.binaryName = binaryName
	}
}

// WithCancel sets the cancel button text.
func WithCancel(cancel string) ClientOption {
	return WithCommandf("SETCANCEL %s\n", cancel)
}

// WithCommand appends an Assuan command that is sent when the connection is
// established.
func WithCommand(command string) ClientOption {
	return func(c *Client) {
		c.commands = append(c.commands, command)
	}
}

// WithCommandf appends an Assuan command that is sent when the connection is
// established, using fmt.Sprintf to format the command.
func WithCommandf(format string, args ...interface{}) ClientOption {
	command := fmt.Sprintf(format, args...)
	return WithCommand(command)
}

// WithDebug tells the pinentry command to print debug messages.
func WithDebug() ClientOption {
	return func(c *Client) {
		c.args = append(c.args, "--debug")
	}
}

// WithDesc sets the description text.
func WithDesc(desc string) ClientOption {
	return WithCommandf("SETDESC %s\n", desc)
}

// WithError sets the error text.
func WithError(error string) ClientOption {
	return WithCommandf("SETERROR %s\n", error)
}

// WithKeyInfo sets a stable key identifier for use with password caching.
func WithKeyInfo(keyInfo string) ClientOption {
	return WithCommandf("SETKEYINFO %s\n", keyInfo)
}

// WithLogger sets the logger.
func WithLogger(logger *zerolog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithNoGlobalGrab instructs pinentry to only grab the password when the window
// is focused.
func WithNoGlobalGrab() ClientOption {
	return func(c *Client) {
		c.args = append(c.args, "--no-global-grab")
	}
}

// WithNotOK sets the text of the non-affirmative response button.
func WithNotOK(notOK string) ClientOption {
	return WithCommandf("SETNOTOK %s\n", notOK)
}

// WithOK sets the text of the OK button.
func WithOK(ok string) ClientOption {
	return WithCommandf("SETOK %s\n", ok)
}

// WithOption sets an option.
func WithOption(option string) ClientOption {
	return WithCommandf("OPTION %s\n", option)
}

// WithOptions sets multiple options.
func WithOptions(options []string) ClientOption {
	return func(c *Client) {
		for _, option := range options {
			command := fmt.Sprintf("OPTION %s\n", option)
			c.commands = append(c.commands, command)
		}
	}
}

// WithPrompt sets the prompt.
func WithPrompt(prompt string) ClientOption {
	return WithCommandf("SETPROMPT %s\n", prompt)
}

// WithQualityBar enables the quality bar.
func WithQualityBar(qualityFunc QualityFunc) ClientOption {
	return func(c *Client) {
		c.commands = append(c.commands, "SETQUALITYBAR\n")
		c.qualityFunc = qualityFunc
	}
}

// WithQualityBarToolTip sets the quality bar tool tip.
func WithQualityBarToolTip(qualityBarTT string) ClientOption {
	return WithCommandf("SETQUALITYBAR_TT %s\n", qualityBarTT)
}

// WithTimeout sets the timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return WithCommandf("SETTIMEOUT %d\n", timeout/time.Second)
}

// WithTitle sets the title.
func WithTitle(title string) ClientOption {
	return WithCommandf("SETTITLE %s\n", title)
}

// NewClient returns a new Client with the given options.
func NewClient(options ...ClientOption) (c *Client, err error) {
	c = &Client{
		binaryName:  "pinentry",
		qualityFunc: func(string) (int, bool) { return 0, false },
	}
	for _, option := range options {
		option(c)
	}

	c.cmd = exec.Command(c.binaryName, c.args...)

	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return
	}

	var stdout io.ReadCloser
	stdout, err = c.cmd.StdoutPipe()
	if err != nil {
		return
	}
	c.stdout = bufio.NewReader(stdout)

	err = c.cmd.Start()
	defer func() {
		if err != nil {
			err = multierr.Append(err, c.Close())
		}
	}()
	if err != nil {
		return
	}

	var line []byte
	line, err = c.readLine()
	if err != nil {
		return
	}
	if !isOK(line) {
		err = newUnexpectedResponseError(line)
		return
	}

	for _, command := range c.commands {
		if err = c.command(command); err != nil {
			return
		}
	}

	return c, nil
}

// Close closes the connection to the pinentry process.
func (c *Client) Close() (err error) {
	defer func() {
		err = multierr.Append(err, c.stdin.Close())
	}()
	if err = c.writeString("BYE\n"); err != nil {
		return
	}
	err = c.readOK()
	return
}

// Confirm asks the user for confirmation.
func (c *Client) Confirm(option string) (bool, error) {
	command := "CONFIRM"
	if option != "" {
		command += " " + option
	}
	command += "\n"
	if err := c.writeString(command); err != nil {
		return false, err
	}
	switch line, err := c.readLine(); {
	case err != nil:
		return false, err
	case isOK(line):
		return true, nil
	case bytes.Equal(line, []byte("ASSUAN_Not_Confirmed")):
		return false, nil
	default:
		return false, newUnexpectedResponseError(line)
	}
}

// GetPIN gets a PIN from the user.
func (c *Client) GetPIN() (pin string, fromCache bool, err error) {
	if err = c.writeString("GETPIN\n"); err != nil {
		return "", false, err
	}
	for {
		var line []byte
		switch line, err = c.readLine(); {
		case err != nil:
			return
		case isOK(line):
			return
		case isData(line):
			pin, err = getPIN(line[2:])
			if err != nil {
				return
			}
		case bytes.Equal(line, []byte("S PASSWORD_FROM_CACHE")):
			fromCache = true
		case bytes.HasPrefix(line, []byte("INQUIRE QUALITY ")):
			pin, err = getPIN(line[16:])
			if err != nil {
				return
			}
			if quality, ok := c.qualityFunc(pin); ok {
				if quality < -100 {
					quality = -100
				} else if quality > 100 {
					quality = 100
				}
				if err = c.writeString(fmt.Sprintf("D %d\n", quality)); err != nil {
					return
				}
				if err = c.writeString("END\n"); err != nil {
					return
				}
			} else {
				if err = c.writeString("CAN\n"); err != nil {
					return
				}
			}
		default:
			err = newUnexpectedResponseError(line)
			return
		}
	}
}

// command writes a command and reads an OK response.
func (c *Client) command(command string) error {
	if err := c.writeString(command); err != nil {
		return err
	}
	return c.readOK()
}

// readLine reads a line, ignoring blank lines and comments.
func (c *Client) readLine() ([]byte, error) {
	for {
		line, _, err := c.stdout.ReadLine()
		if err == nil && bytes.HasPrefix(line, []byte("ERR ")) {
			err = fmt.Errorf("pinentry: %s", line[4:])
		}
		if c.logger != nil {
			c.logger.Err(err).Bytes("line", line).Msg("readLine")
		}
		switch {
		case isBlank(line):
		case isComment(line):
		default:
			return line, err
		}
	}
}

// readOK reads an OK response.
func (c *Client) readOK() error {
	switch line, err := c.readLine(); {
	case err != nil:
		return err
	case isOK(line):
		return nil
	case isError(line):
		return newError(line)
	default:
		return newUnexpectedResponseError(line)
	}
}

// writeString writes a single line.
func (c *Client) writeString(line string) error {
	_, err := c.stdin.Write([]byte(line))
	if c.logger != nil {
		c.logger.Err(err).Str("line", line).Msg("write")
	}
	return err
}

// getPIN parses a PIN from suffix.
func getPIN(suffix []byte) (password string, err error) {
	return url.QueryUnescape(string(suffix))
}

// isBlank returns if line is blank.
func isBlank(line []byte) bool {
	return len(bytes.TrimSpace(line)) == 0
}

// isComment returns if line is a comment.
func isComment(line []byte) bool {
	return bytes.HasPrefix(line, []byte("#"))
}

// isData returns if line is a data line.
func isData(line []byte) bool {
	return bytes.HasPrefix(line, []byte("D "))
}

// isError returns if line is an error.
func isError(line []byte) bool {
	return bytes.HasPrefix(line, []byte("ERR "))
}

func isOK(line []byte) bool {
	return bytes.HasPrefix(line, []byte("OK"))
}

// newError returns an error parsed from line.
func newError(line []byte) error {
	match := errorRx.FindSubmatch(line)
	if match == nil {
		return newUnexpectedResponseError(line)
	}
	code, _ := strconv.Atoi(string(match[1]))
	return &AssuanError{
		Code:        code,
		Description: string(match[2]),
	}
}