//go:generate mockgen -destination=mockprocess.go -package=pinentry . Process

package pinentry

import (
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientClose(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientArgs(t *testing.T) {
	for i, tc := range []struct {
		clientOptions []ClientOption
		expectedArgs  []string
	}{
		{
			clientOptions: []ClientOption{
				WithArgs([]string{
					"--arg1",
					"--arg2",
				}),
			},
			expectedArgs: []string{
				"--arg1",
				"--arg2",
			},
		},
		{
			clientOptions: []ClientOption{
				WithDebug(),
			},
			expectedArgs: []string{
				"--debug",
			},
		},
		{
			clientOptions: []ClientOption{
				WithNoGlobalGrab(),
			},
			expectedArgs: []string{
				"--no-global-grab",
			},
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			p := newMockProcess(t)

			p.expectStart("pinentry", tc.expectedArgs)
			clientOptions := []ClientOption{WithProcess(p)}
			clientOptions = append(clientOptions, tc.clientOptions...)
			c, err := NewClient(clientOptions...)
			require.NoError(t, err)

			p.expectClose()
			require.NoError(t, c.Close())
		})
	}
}

func TestClientBinaryName(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry-test", nil)
	c, err := NewClient(
		WithBinaryName("pinentry-test"),
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientCommands(t *testing.T) {
	for i, tc := range []struct {
		clientOptions   []ClientOption
		expectedCommand string
	}{
		{
			clientOptions: []ClientOption{
				WithCancel("cancel"),
			},
			expectedCommand: "SETCANCEL cancel",
		},
		{
			clientOptions: []ClientOption{
				WithDesc("desc"),
			},
			expectedCommand: "SETDESC desc",
		},
		{
			clientOptions: []ClientOption{
				WithError("error"),
			},
			expectedCommand: "SETERROR error",
		},
		{
			clientOptions: []ClientOption{
				WithKeyInfo("keyinfo"),
			},
			expectedCommand: "SETKEYINFO keyinfo",
		},
		{
			clientOptions: []ClientOption{
				WithNotOK("notok"),
			},
			expectedCommand: "SETNOTOK notok",
		},
		{
			clientOptions: []ClientOption{
				WithOK("ok"),
			},
			expectedCommand: "SETOK ok",
		},
		{
			clientOptions: []ClientOption{
				WithOption("option"),
			},
			expectedCommand: "OPTION option",
		},
		{
			clientOptions: []ClientOption{
				WithOptions([]string{
					"option",
				}),
			},
			expectedCommand: "OPTION option",
		},
		{
			clientOptions: []ClientOption{
				WithPrompt("prompt"),
			},
			expectedCommand: "SETPROMPT prompt",
		},
		{
			clientOptions: []ClientOption{
				WithQualityBarToolTip("qualitybartooltip"),
			},
			expectedCommand: "SETQUALITYBAR_TT qualitybartooltip",
		},
		{
			clientOptions: []ClientOption{
				WithTimeout(time.Second),
			},
			expectedCommand: "SETTIMEOUT 1",
		},
		{
			clientOptions: []ClientOption{
				WithTitle("title"),
			},
			expectedCommand: "SETTITLE title",
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			p := newMockProcess(t)

			p.expectStart("pinentry", nil)
			p.expectWritelnOK(tc.expectedCommand)
			clientOptions := []ClientOption{WithProcess(p)}
			clientOptions = append(clientOptions, tc.clientOptions...)
			c, err := NewClient(clientOptions...)
			require.NoError(t, err)

			p.expectClose()
			require.NoError(t, c.Close())
		})
	}
}

func TestClientGetPIN(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	expectedPIN := "abc"
	expectedFromCache := false
	p.expectWriteln("GETPIN")
	p.expectReadLine("D " + expectedPIN)
	p.expectReadLine("OK")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.NoError(t, err)
	assert.Equal(t, expectedPIN, actualPIN)
	assert.Equal(t, expectedFromCache, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientConfirm(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	expectedConfirm := true
	p.expectWriteln("CONFIRM confirm")
	p.expectReadLine("OK")
	actualConfirm, err := c.Confirm("confirm")
	require.NoError(t, err)
	assert.Equal(t, expectedConfirm, actualConfirm)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientConfirmCancel(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectWriteln("CONFIRM confirm")
	p.expectReadLine("ERR 83886179 Operation cancelled <Pinentry>")
	actualConfirm, err := c.Confirm("confirm")
	require.Error(t, err)
	assert.True(t, IsCancelled(err))
	assert.Equal(t, false, actualConfirm)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientGetPINCancel(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectWriteln("GETPIN")
	p.expectReadLine("ERR 83886179 Operation cancelled <Pinentry>")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.Error(t, err)
	assert.True(t, IsCancelled(err))
	assert.Equal(t, "", actualPIN)
	assert.Equal(t, false, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientGetPINFromCache(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	expectedPIN := "abc"
	expectedFromCache := true
	p.expectWriteln("GETPIN")
	p.expectReadLine("S PASSWORD_FROM_CACHE")
	p.expectReadLine("D " + expectedPIN)
	p.expectReadLine("OK")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.NoError(t, err)
	assert.Equal(t, expectedPIN, actualPIN)
	assert.Equal(t, expectedFromCache, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientGetPINQualityBar(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	p.expectWritelnOK("SETQUALITYBAR")
	c, err := NewClient(
		WithProcess(p),
		WithQualityBar(func(pin string) (int, bool) {
			return 10 * len(pin), true
		}),
	)
	require.NoError(t, err)

	expectedPIN := "abc"
	expectedFromCache := false
	p.expectWriteln("GETPIN")
	p.expectReadLine("INQUIRE QUALITY a")
	p.expectWriteln("D 10")
	p.expectWriteln("END")
	p.expectReadLine("INQUIRE QUALITY ab")
	p.expectWriteln("D 20")
	p.expectWriteln("END")
	p.expectReadLine("INQUIRE QUALITY abc")
	p.expectWriteln("D 30")
	p.expectWriteln("END")
	p.expectReadLine("D abc")
	p.expectReadLine("OK")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.NoError(t, err)
	assert.Equal(t, expectedPIN, actualPIN)
	assert.Equal(t, expectedFromCache, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientGetPINQualityBarCancel(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	p.expectWritelnOK("SETQUALITYBAR")
	c, err := NewClient(
		WithProcess(p),
		WithQualityBar(func(pin string) (int, bool) {
			return 0, false
		}),
	)
	require.NoError(t, err)

	expectedPIN := "abc"
	expectedFromCache := false
	p.expectWriteln("GETPIN")
	p.expectReadLine("INQUIRE QUALITY a")
	p.expectWriteln("CAN")
	p.expectReadLine("INQUIRE QUALITY ab")
	p.expectWriteln("CAN")
	p.expectReadLine("INQUIRE QUALITY abc")
	p.expectWriteln("CAN")
	p.expectReadLine("D abc")
	p.expectReadLine("OK")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.NoError(t, err)
	assert.Equal(t, expectedPIN, actualPIN)
	assert.Equal(t, expectedFromCache, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientGetPINineUnexpectedResponse(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectWriteln("GETPIN")
	p.expectReadLine("unexpected response")
	actualPIN, actualFromCache, err := c.GetPIN()
	require.Error(t, err)
	assert.ErrorIs(t, err, UnexpectedResponseError{
		line: "unexpected response",
	})
	assert.Equal(t, "", actualPIN)
	assert.Equal(t, false, actualFromCache)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientReadLineIgnoreBlank(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	p.expectReadLine("")
	p.expectReadLine("\t")
	p.expectReadLine("\n")
	p.expectReadLine(" ")
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectClose()
	require.NoError(t, c.Close())
}

func TestClientReadLineIgnoreComment(t *testing.T) {
	p := newMockProcess(t)

	p.expectStart("pinentry", nil)
	p.expectReadLine("#")
	p.expectReadLine("# comment")
	c, err := NewClient(
		WithProcess(p),
	)
	require.NoError(t, err)

	p.expectClose()
	require.NoError(t, c.Close())
}

func newMockProcess(t *testing.T) *MockProcess {
	return NewMockProcess(gomock.NewController(t))
}

func (p *MockProcess) expectClose() {
	p.expectWriteln("BYE")
	p.expectReadLine("OK closing connection")
	p.EXPECT().Close().Return(nil)
}

func (p *MockProcess) expectReadLine(line string) {
	p.EXPECT().ReadLine().Return([]byte(line), false, nil)
}

func (p *MockProcess) expectStart(name string, args []string) {
	p.EXPECT().Start(name, args).Return(nil)
	p.expectReadLine("OK Pleased to meet you")
}

func (p *MockProcess) expectWriteln(line string) {
	p.EXPECT().Write([]byte(line+"\n")).Return(len(line)+1, nil)
}

func (p *MockProcess) expectWritelnOK(line string) {
	p.expectWriteln(line)
	p.expectReadLine("OK")
}
