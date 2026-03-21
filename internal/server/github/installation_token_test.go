package github

import (
	"testing"
	"time"
)

func TestTokenCacheKey_DifferentInputsProduceDifferentKeys(t *testing.T) {
	k1 := newTokenCacheKey([]string{"repo-a"}, Permissions{"contents": "read"})
	k2 := newTokenCacheKey([]string{"repo-b"}, Permissions{"contents": "read"})
	k3 := newTokenCacheKey([]string{"repo-a"}, Permissions{"contents": "write"})

	if k1 == k2 {
		t.Error("different repos produced the same cache key")
	}
	if k1 == k3 {
		t.Error("different permissions produced the same cache key")
	}
}

func TestTokenCacheKey_RepoOrderDoesNotMatter(t *testing.T) {
	k1 := newTokenCacheKey([]string{"repo-a", "repo-b"}, Permissions{"contents": "read"})
	k2 := newTokenCacheKey([]string{"repo-b", "repo-a"}, Permissions{"contents": "read"})

	if k1 != k2 {
		t.Error("same repos in different order produced different cache keys")
	}
}

func TestInstallationToken_Expired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		token *InstallationToken
		want  bool
	}{
		{"nil token", nil, true},
		{"expired in the past", &InstallationToken{ExpiresAt: now.Add(-1 * time.Minute)}, true},
		{"expires in 10 minutes (within buffer)", &InstallationToken{ExpiresAt: now.Add(10 * time.Minute)}, true},
		{"expires in 31 minutes (outside buffer)", &InstallationToken{ExpiresAt: now.Add(31 * time.Minute)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}
