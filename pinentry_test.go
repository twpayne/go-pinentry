package pinentry

import (
	"strconv"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestEscapeUnescape(t *testing.T) {
	for i, tc := range []struct {
		unescaped string
		escaped   string
	}{
		{
			unescaped: "",
			escaped:   "",
		},
		{
			unescaped: "a",
			escaped:   "a",
		},
		{
			unescaped: "\n",
			escaped:   "%0A",
		},
		{
			unescaped: "\r",
			escaped:   "%0D",
		},
		{
			unescaped: "%",
			escaped:   "%25",
		},
		{
			unescaped: "a\r\n%b",
			escaped:   "a%0D%0A%25b",
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actualEscaped := escape(tc.unescaped)
			assert.Equal(t, tc.escaped, actualEscaped)
			actualUnescaped := unescape([]byte(tc.escaped))
			assert.Equal(t, tc.unescaped, string(actualUnescaped))
		})
	}
}

func TestUnescape(t *testing.T) {
	for i, tc := range []struct {
		s                 string
		expectedUnescaped string
	}{
		{
			s:                 "%",
			expectedUnescaped: "%",
		},
		{
			s:                 "%0",
			expectedUnescaped: "%0",
		},
		{
			s:                 "%0a",
			expectedUnescaped: "%0a",
		},
		{
			s:                 "%0A%",
			expectedUnescaped: "\n%",
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actualUnescaped := unescape([]byte(tc.s))
			assert.Equal(t, tc.expectedUnescaped, string(actualUnescaped))
		})
	}
}
