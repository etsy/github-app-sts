package testutil

import (
	"os"
	"strings"
	"testing"
)

// SkipUnlessIntegrationTest skips the test unless the INTEGRATION_TEST
// environment variable includes name (comma-separated) or is set to "all".
func SkipUnlessIntegrationTest(t *testing.T, name string) {
	t.Helper()

	val := os.Getenv("INTEGRATION_TEST")

	if val == "" {
		t.Skipf("set INTEGRATION_TEST=%s to run", name)
	}

	if val == "all" {
		return
	}

	for _, v := range strings.Split(val, ",") {
		if strings.TrimSpace(v) == name {
			return
		}
	}

	t.Skipf("INTEGRATION_TEST=%q does not include %q", val, name)
}

// MustGetenv returns the value of the environment variable or fails the test.
func MustGetenv(t *testing.T, key string) string {
	t.Helper()

	if val := os.Getenv(key); val != "" {
		return val
	}

	t.Fatalf("missing or empty environment variable '%s'", key)

	return ""
}

// GetenvOrDefault returns the value of the environment variable, or the
// fallback if it is empty or unset.
func GetenvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	return fallback
}
