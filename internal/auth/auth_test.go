package auth

import (
	"context"
	"errors"
	"testing"
)

func TestB1HasNoTokensForAnyoneAndNoReviewerToken(t *testing.T) {
	var s TokenSource = NoTokens{}
	if tok, err := s.Token(context.Background(), Subject{Tenant: "t", Member: "m"}, "c"); tok != "" || !errors.Is(err, ErrNoToken) {
		t.Fatalf("%q %v", tok, err)
	}
	if tok, err := s.Refresh(context.Background(), Subject{}, "c", "old"); tok != "" || !errors.Is(err, ErrNoToken) {
		t.Fatalf("%q %v", tok, err)
	}
	var r ReviewerSource = NoReviewer{}
	if tok, err := r.Token(context.Background(), "c"); tok != "" || err != nil {
		t.Fatalf("%q %v", tok, err)
	}
}
