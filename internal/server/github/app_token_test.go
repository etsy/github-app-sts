package github

import (
	"testing"
	"time"
)

func TestAppToken_Expired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		token *AppToken
		want  bool
	}{
		{"nil token", nil, true},
		{"expired in the past", &AppToken{exp: now.Add(-1 * time.Minute)}, true},
		{"expires in 30 seconds (within buffer)", &AppToken{exp: now.Add(30 * time.Second)}, true},
		{"expires in 2 minutes (outside buffer)", &AppToken{exp: now.Add(2 * time.Minute)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}
