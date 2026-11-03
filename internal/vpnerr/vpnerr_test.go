package vpnerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCode(t *testing.T) {
	specific := errors.New("specific")
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{specific, 1},
		{fmt.Errorf("%w: %w", ErrUsage, specific), 2},
		{fmt.Errorf("%w: %w", ErrAuth, specific), 3},
		{fmt.Errorf("wrap: %w", fmt.Errorf("%w: %w", ErrTunnel, specific)), 4},
		{fmt.Errorf("%w", ErrPermission), 5},
		{fmt.Errorf("%w", ErrNetConfig), 6},
		{fmt.Errorf("%w", ErrRejected), 7},
	}
	for _, c := range cases {
		if got := ExitCode(c.err); got != c.want {
			t.Errorf("ExitCode(%v)=%d want %d", c.err, got, c.want)
		}
	}
}
