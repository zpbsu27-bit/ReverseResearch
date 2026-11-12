//go:build windows

package consolelog

import "testing"

func TestConsoleAttributesMatchPresentationContract(t *testing.T) {
	tests := []struct {
		color Color
		want  uint16
	}{
		{ColorWhite, 0x000f},
		{ColorDim, 0x0007},
		{ColorStatus, 0x000b},
		{ColorGreen, 0x000a},
		{ColorYellow, 0x000e},
		{ColorRed, 0x000c},
		{ColorTunnel, 0x000d},
	}
	for _, tc := range tests {
		if got := consoleAttribute(tc.color); got != tc.want {
			t.Fatalf("consoleAttribute(%d)=0x%04x want=0x%04x", tc.color, got, tc.want)
		}
	}
}
