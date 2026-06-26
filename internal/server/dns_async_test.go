package server

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChallengeProgress_DefaultAndFail(t *testing.T) {
	p := &challengeProgress{status: "processing"}

	status, errType, errMsg := p.snapshot()
	if status != "processing" || errType != "" || errMsg != "" {
		t.Fatalf("initial snapshot = (%q, %q, %q), want (processing, \"\", \"\")", status, errType, errMsg)
	}

	p.fail("dns", "no TXT record published")

	status, errType, errMsg = p.snapshot()
	if status != "invalid" {
		t.Fatalf("status after fail = %q, want invalid", status)
	}
	if errType != "dns" || errMsg != "no TXT record published" {
		t.Fatalf("error after fail = (%q, %q), want (dns, no TXT record published)", errType, errMsg)
	}
}

// TestChallengeProgress_ConcurrentAccess exercises the mutex under -race: a
// concurrent fail and many snapshots must not race and must converge to invalid.
func TestChallengeProgress_ConcurrentAccess(t *testing.T) {
	p := &challengeProgress{status: "processing"}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.fail("serverInternal", "trigger failed")
	}()
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = p.snapshot()
		}()
	}
	wg.Wait()

	if status, _, _ := p.snapshot(); status != "invalid" {
		t.Fatalf("final status = %q, want invalid", status)
	}
}

func TestBeginChallengeProc_Idempotent(t *testing.T) {
	h := &Handler{}

	prog, started := h.beginChallengeProc("chal-1")
	if !started {
		t.Fatal("first call should report started=true")
	}
	if prog == nil || prog.status != "processing" {
		t.Fatalf("first progress = %+v, want non-nil processing", prog)
	}

	// A second call for the same challenge must not start new work and must
	// return the same progress instance so a recorded failure stays visible.
	prog.fail("dns", "boom")
	again, started := h.beginChallengeProc("chal-1")
	if started {
		t.Fatal("second call should report started=false")
	}
	if again != prog {
		t.Fatal("second call returned a different progress instance")
	}
	if status, _, _ := again.snapshot(); status != "invalid" {
		t.Fatalf("second progress status = %q, want invalid", status)
	}

	// A different challenge ID is tracked independently.
	if _, started := h.beginChallengeProc("chal-2"); !started {
		t.Fatal("distinct challenge id should report started=true")
	}
}

// TestBeginChallengeProc_RaceSingleStarter ensures that under concurrent first
// answers for the same challenge, exactly one caller is told to start work.
func TestBeginChallengeProc_RaceSingleStarter(t *testing.T) {
	h := &Handler{}

	const n = 50
	var wg sync.WaitGroup
	starts := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, started := h.beginChallengeProc("same")
			starts <- started
		}()
	}
	wg.Wait()
	close(starts)

	got := 0
	for s := range starts {
		if s {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("started count = %d, want exactly 1", got)
	}
}

func TestBeginChallengeProc_EvictsStaleEntries(t *testing.T) {
	h := &Handler{}

	// A failed record older than the retention window must be reclaimed; a
	// recent one must survive.
	h.challengeProc.Store("stale", &challengeProgress{
		status:    "invalid",
		createdAt: time.Now().Add(-challengeProcRetention - time.Minute),
	})
	h.challengeProc.Store("fresh", &challengeProgress{
		status:    "invalid",
		createdAt: time.Now(),
	})

	// Starting a new challenge triggers the opportunistic sweep.
	if _, started := h.beginChallengeProc("new"); !started {
		t.Fatal("new challenge should report started=true")
	}

	if _, ok := h.challengeProc.Load("stale"); ok {
		t.Fatal("stale entry should have been evicted")
	}
	if _, ok := h.challengeProc.Load("fresh"); !ok {
		t.Fatal("fresh entry should have been retained")
	}
	if _, ok := h.challengeProc.Load("new"); !ok {
		t.Fatal("newly started entry should be present")
	}
}

func TestACMEProblem(t *testing.T) {
	p := acmeProblem("dns", "the record did not propagate")

	if got := p["type"]; got != "urn:ietf:params:acme:error:dns" {
		t.Fatalf("type = %v, want urn:ietf:params:acme:error:dns", got)
	}
	if got, ok := p["detail"].(string); !ok || !strings.Contains(got, "did not propagate") {
		t.Fatalf("detail = %v, want it to contain the supplied detail", p["detail"])
	}
}
