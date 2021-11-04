package pinentry

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/multierr"
)

const (
	OptionAllowExternalPasswordCache = "allow-external-password-cache"
	OptionDefaultOK                  = "default-ok"
	OptionDefaultCancel              = "default-cancel"
	OptionDefaultPrompt              = "default-prompt"
	OptionTTYName                    = "ttyname"
	OptionTTYType                    = "ttytype"
	OptionLCCType                    = "lc-ctype"
)

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

type QualityFunc func(string) int

type Client struct {
	name        string
	args        []string
	commands    []string
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      *bufio.Reader
	qualityFunc QualityFunc
	logger      *zerolog.Logger
}

type ClientOption func(*Client)

func WithName(name string) ClientOption {
	return func(c *Client) {
		c.name = name
	}
}

func WithCancel(cancel string) ClientOption {
	return WithCommandf("SETCANCEL %s\n", cancel)
}

func WithCommand(command string) ClientOption {
	return func(c *Client) {
		c.commands = append(c.commands, command)
	}
}

func WithCommandf(format string, args ...interface{}) ClientOption {
	command := fmt.Sprintf(format, args...)
	return WithCommand(command)
}

func WithDebug() ClientOption {
	return func(c *Client) {
		c.args = append(c.args, "--debug")
	}
}

func WithDesc(desc string) ClientOption {
	return WithCommandf("SETDESC %s\n", desc)
}

func WithError(error string) ClientOption {
	return WithCommandf("SETERROR %s\n", error)
}

func WithKeyInfo(keyInfo string) ClientOption {
	return WithCommandf("SETKEYINFO %s\n", keyInfo)
}

func WithLogger(logger *zerolog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

func WithNoGlobalGrab() ClientOption {
	return func(c *Client) {
		c.args = append(c.args, "--no-global-grab")
	}
}

func WithNotOK(notOK string) ClientOption {
	return WithCommandf("SETNOTOK %s\n", notOK)
}

func WithOK(ok string) ClientOption {
	return WithCommandf("SETOK %s\n", ok)
}

func WithOption(option string) ClientOption {
	return WithCommandf("OPTION %s\n", option)
}

func WithPrompt(prompt string) ClientOption {
	return WithCommandf("SETPROMPT %s\n", prompt)
}

func WithQualityBar(qualityFunc func(string) int) ClientOption {
	return func(c *Client) {
		c.commands = append(c.commands, "SETQUALITYBAR\n")
		c.qualityFunc = qualityFunc
	}
}

func WithQualityBarTT(qualityBarTT string) ClientOption {
	return WithCommandf("SETQUALITYBAR_TT %s\n", qualityBarTT)
}

func WithTimeout(timeout time.Duration) ClientOption {
	return WithCommandf("SETTIMEOUT %d\n", timeout/time.Second)
}

func WithTitle(title string) ClientOption {
	return WithCommandf("SETTITLE %s\n", title)
}

func NewClient(options ...ClientOption) (c *Client, err error) {
	c = &Client{
		name:        "pinentry",
		qualityFunc: func(string) int { return 0 },
	}
	for _, option := range options {
		option(c)
	}

	c.cmd = exec.Command(c.name, c.args...)

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
	if !bytes.HasPrefix(line, []byte("OK")) {
		err = newUnexpectedResponseError(line)
		return
	}

	for _, command := range c.commands {
		if err = c.Send(command); err != nil {
			return
		}
	}

	return c, nil
}

func (c *Client) Close() error {
	return c.stdin.Close()
}

func (c *Client) Confirm(option string) (bool, error) {
	command := "CONFIRM"
	if option != "" {
		command += " " + option
	}
	command += "\n"
	if err := c.write([]byte(command)); err != nil {
		return false, err
	}
	switch line, err := c.readLine(); {
	case err != nil:
		return false, err
	case bytes.Equal(line, []byte("OK")):
		return true, nil
	case bytes.Equal(line, []byte("ASSUAN_Not_Confirmed")):
		return false, nil
	default:
		return false, newUnexpectedResponseError(line)
	}
}

func (c *Client) GetPIN() (pin string, fromCache bool, err error) {
	if err = c.write([]byte("GETPIN\n")); err != nil {
		return "", false, err
	}
	for {
		var line []byte
		switch line, err = c.readLine(); {
		case err != nil:
			return
		case bytes.HasPrefix(line, []byte("D ")):
			pin, err = getPIN(line[2:])
			if err != nil {
				return
			}
		case bytes.Equal(line, []byte("OK")):
			return
		case bytes.Equal(line, []byte("S PASSWORD_FROM_CACHE")):
			fromCache = true
		case bytes.HasPrefix(line, []byte("INQUIRE QUALITY ")):
			pin, err = getPIN(line[16:])
			if err != nil {
				return
			}
			quality := c.qualityFunc(pin)
			if quality < -100 {
				quality = -100
			} else if quality > 100 {
				quality = 1000
			}
			// FIXME the format of the response here is not recognized by pinentry-mac
			if err = c.write([]byte(fmt.Sprintf("D %d\n", quality))); err != nil {
				return
			}
		default:
			err = newUnexpectedResponseError(line)
			return
		}
	}
}

func (c *Client) Send(command string) error {
	if err := c.write([]byte(command)); err != nil {
		return err
	}
	return c.readOK()
}

func (c *Client) readLine() ([]byte, error) {
	line, _, err := c.stdout.ReadLine()
	if err == nil && bytes.HasPrefix(line, []byte("ERR ")) {
		err = fmt.Errorf("pinentry: %s", line[4:])
	}
	if c.logger != nil {
		c.logger.Err(err).Bytes("line", line).Msg("readLine")
	}
	return line, err
}

func (c *Client) readOK() error {
	switch line, err := c.readLine(); {
	case err != nil:
		return err
	case bytes.Equal(line, []byte("OK")):
		return nil
	default:
		return newUnexpectedResponseError(line)
	}
}

func (c *Client) write(line []byte) error {
	_, err := c.stdin.Write(line)
	if c.logger != nil {
		c.logger.Err(err).Bytes("line", line).Msg("write")
	}
	return err
}

func getPIN(suffix []byte) (password string, err error) {
	return url.QueryUnescape(string(suffix))
}
