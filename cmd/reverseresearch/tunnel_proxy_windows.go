//go:build windows

package main

import "golang.org/x/sys/windows/registry"

func readSystemTunnelProxy() (systemTunnelProxy, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return systemTunnelProxy{}, nil
	}
	defer key.Close()
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return systemTunnelProxy{}, nil
	}
	value, _, err := key.GetStringValue("ProxyServer")
	if err != nil {
		return systemTunnelProxy{}, nil
	}
	address, err := selectSystemHTTPSProxy(value)
	if err != nil {
		return systemTunnelProxy{}, err
	}
	bypass, _, _ := key.GetStringValue("ProxyOverride")
	return systemTunnelProxy{address: address, bypass: bypass}, nil
}
