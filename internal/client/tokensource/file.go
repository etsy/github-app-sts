package tokensource

import (
	"fmt"
	"os"
	"strings"
)

// FromFile reads an OIDC identity token from the given file path.
func FromFile(path string) (string, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}

	token := strings.TrimSpace(string(data))

	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}

	return token, nil
}
