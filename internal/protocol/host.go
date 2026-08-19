package protocol

import (
	"net"
	"os"
	"sort"
	"strings"
)

func hostMetadata() (string, []string) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	interfaces, err := net.Interfaces()
	if err != nil {
		return hostname, nil
	}
	unique := make(map[string]struct{})
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.IsPrivate() {
				unique[ip.String()] = struct{}{}
			}
		}
	}
	privateIPs := make([]string, 0, len(unique))
	for address := range unique {
		privateIPs = append(privateIPs, address)
	}
	sort.Strings(privateIPs)
	if len(privateIPs) > 8 {
		privateIPs = privateIPs[:8]
	}
	return hostname, privateIPs
}
