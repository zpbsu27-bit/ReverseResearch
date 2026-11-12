//go:build !windows

package consolelog

import (
	"fmt"
	"io"
)

func writeConsole(writer io.Writer, _ Color, value string) {
	_, _ = fmt.Fprintln(writer, value)
}

func SetTitle(string) {}
