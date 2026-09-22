//go:build linux

package apps

import "net/url"

func applicationCanonicalURL(raw string) (*url.URL, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, "", ErrIntegrity
	}
	port := ""
	switch parsed.Scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	default:
		return nil, "", ErrIntegrity
	}
	if parsed.Port() != "" && parsed.Port() != port {
		return nil, "", ErrIntegrity
	}
	return parsed, port, nil
}
