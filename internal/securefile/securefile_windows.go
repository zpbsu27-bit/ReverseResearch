//go:build windows

package securefile

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func RestrictFile(path string) error {
	return restrict(path, false)
}

func RestrictDir(path string) error {
	return restrict(path, true)
}

func restrict(path string, directory bool) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current user SID: %w", err)
	}
	sid := user.User.Sid.String()
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;" + sid + ")(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read private DACL: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply private DACL to %s: %w", path, err)
	}
	return nil
}
