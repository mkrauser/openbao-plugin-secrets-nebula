package nebula

import (
	"fmt"
	"net"
	"strings"
)

func formatFingerprint(s string) string {
	var result strings.Builder
	for i, c := range s {
		// Add the current character to the result
		result.WriteRune(c)

		// Add a colon after every 4th character (except after the last character)
		if (i+1)%4 == 0 && i != len(s)-1 {
			result.WriteRune(':')
		}
	}
	return result.String()
}

func parseCIDRList(input string) ([]*net.IPNet, error) {
	var ipNets []*net.IPNet
	for _, rs := range strings.Split(input, ",") {
		rs = strings.Trim(rs, " ")
		if rs != "" {
			_, ipNet, err := net.ParseCIDR(rs)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR definition: %s", err)
			}
			ipNets = append(ipNets, ipNet)
		}
	}
	return ipNets, nil
}

func parseGroups(groups string) []string {
	var _groups []string
	if groups != "" {
		for _, rg := range strings.Split(groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				_groups = append(_groups, g)
			}
		}
	}
	return _groups
}
