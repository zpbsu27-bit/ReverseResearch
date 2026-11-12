//go:build windows

package consolelog

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	setConsoleTextAttribute = kernel32.NewProc("SetConsoleTextAttribute")
	setConsoleTitleProc     = kernel32.NewProc("SetConsoleTitleW")
)

func writeConsole(writer io.Writer, color Color, value string) {
	file, ok := writer.(*os.File)
	if !ok {
		_, _ = fmt.Fprintln(writer, value)
		return
	}
	handle := windows.Handle(file.Fd())
	var original windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(handle, &original); err != nil {
		_, _ = fmt.Fprintln(writer, value)
		return
	}
	if !setConsoleAttribute(handle, consoleAttribute(color)) {
		_, _ = fmt.Fprintln(writer, value)
		return
	}
	defer setConsoleAttribute(handle, original.Attributes)
	_, _ = fmt.Fprintln(writer, value)
}

func setConsoleAttribute(handle windows.Handle, attribute uint16) bool {
	result, _, _ := setConsoleTextAttribute.Call(uintptr(handle), uintptr(attribute))
	return result != 0
}

func consoleAttribute(color Color) uint16 {
	const (
		foregroundBlue      = 0x0001
		foregroundGreen     = 0x0002
		foregroundRed       = 0x0004
		foregroundIntensity = 0x0008
	)
	switch color {
	case ColorDim:
		return foregroundRed | foregroundGreen | foregroundBlue
	case ColorStatus:
		return foregroundGreen | foregroundBlue | foregroundIntensity
	case ColorGreen:
		return foregroundGreen | foregroundIntensity
	case ColorYellow:
		return foregroundRed | foregroundGreen | foregroundIntensity
	case ColorRed:
		return foregroundRed | foregroundIntensity
	case ColorTunnel:
		return foregroundRed | foregroundBlue | foregroundIntensity
	default:
		return foregroundRed | foregroundGreen | foregroundBlue | foregroundIntensity
	}
}

func SetTitle(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "ReverseResearch"
	}
	pointer, err := windows.UTF16PtrFromString(value)
	if err == nil {
		_, _, _ = setConsoleTitleProc.Call(uintptr(unsafe.Pointer(pointer)))
	}
}
