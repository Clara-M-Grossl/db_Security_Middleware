package middleware

import (
	"os"
	"strings"
)

func EnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getMapKeys(m map[string]StatementMetaData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
