package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func selectSystemHTTPSProxy(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	protocol, _, hasEquals := strings.Cut(value, "=")
	protocol = strings.TrimSpace(protocol)
	isProtocolMap := hasEquals && (strings.EqualFold(protocol, "https") || strings.EqualFold(protocol, "http") || strings.EqualFold(protocol, "ftp") || strings.EqualFold(protocol, "socks"))
	if !strings.Contains(value, ";") && !isProtocolMap {
		return validateSystemProxyURL(value)
	}
	for _, part := range strings.Split(value, ";") {
		protocol, address, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(protocol), "https") {
			if strings.TrimSpace(address) == "" {
				return "", nil
			}
			return validateSystemProxyURL(strings.TrimSpace(address))
		}
	}
	return "", nil // Do not turn an HTTP-only preference into HTTPS routing.
}

func validateSystemProxyURL(value string) (string, error) {
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("tunnel proxy has an invalid address")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("tunnel proxy uses an unsupported scheme")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("tunnel proxy has an invalid port")
		}
	}
	return u.String(), nil
}
