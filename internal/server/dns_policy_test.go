package server

import "testing"

func TestQuorumRequirement(t *testing.T) {
	tests := []struct {
		name   string
		total  int
		quorum int
		want   int
	}{
		{name: "all by default", total: 5, quorum: 0, want: 5},
		{name: "full quorum", total: 5, quorum: 100, want: 5},
		{name: "eighty percent", total: 5, quorum: 80, want: 4},
		{name: "sixty six percent rounds up", total: 3, quorum: 66, want: 2},
		{name: "cap over hundred", total: 4, quorum: 120, want: 4},
		{name: "empty set", total: 0, quorum: 100, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := quorumRequirement(tc.total, tc.quorum); got != tc.want {
				t.Fatalf("quorumRequirement(%d,%d)=%d want %d", tc.total, tc.quorum, got, tc.want)
			}
		})
	}
}

func TestValidateDelegatedTarget(t *testing.T) {
	if err := validateDelegatedTarget("_acme-challenge.foo.delegate.example", nil); err != nil {
		t.Fatalf("expected nil for empty allow list, got %v", err)
	}
	if err := validateDelegatedTarget("_acme-challenge.foo.delegate.example", []string{"delegate.example"}); err != nil {
		t.Fatalf("expected allowed suffix match, got %v", err)
	}
	if err := validateDelegatedTarget("_acme-challenge.foo.delegate.example", []string{"other.example"}); err == nil {
		t.Fatal("expected error for non-matching suffix")
	}
}
