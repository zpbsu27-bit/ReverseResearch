//go:build !windows

package main

func readSystemTunnelProxy() (systemTunnelProxy, error) { return systemTunnelProxy{}, nil }
