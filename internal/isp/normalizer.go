package isp

import (
	"strings"
	"unicode"
)

var unresolvedSet = map[string]bool{
	"":             true,
	"-":            true,
	"(none)":       true,
	"Resolving...": true,
	"Rate Limited": true,
	"Unknown ISP":  true,
	"Unknown":      true,
}

func CleanISPName(raw string) string {
	val := strings.TrimSpace(raw)
	if unresolvedSet[val] {
		return "Unknown ISP"
	}

	// Strip ASN prefix if present, e.g. "AS7418 TELEFÓNICA CHILE S.A." -> "TELEFÓNICA CHILE S.A."
	parts := strings.SplitN(val, " ", 2)
	if len(parts) == 2 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		asnNum := parts[0][2:]
		if isAllDigits(asnNum) {
			val = strings.TrimSpace(parts[1])
		}
	}

	// Fix corrupted UTF-8 encodings or legacy variations for Telefónica Chile
	upper := strings.ToUpper(val)
	if strings.Contains(upper, "TELEF") && strings.Contains(upper, "NICA") {
		val = "TELEF\u00d3NICA CHILE S.A."
	}

	// Consolidate WOM variants
	up := strings.ToUpper(val)
	if up == "WOM SPA" || up == "WOM S.A." || up == "WOM" {
		val = "WOM S.A."
	}

	return val
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
