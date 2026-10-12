package services

import (
	"sync"
	"testing"
)

// The process's Slack app is set from the policy gate's VerifyUntilReady
// goroutine (cmd/main.go) while request handlers read it
// (NewDefaultSlackIntegrationController -> DefaultSlackService). Run with
// -race: a plain package variable there is reported as a DATA RACE (review
// fix, P2 Slack).
func TestSlackDefaultServiceIsRaceFree(t *testing.T) {
	t.Cleanup(func() { SetDefaultSlackService(nil) })
	a, b := &SlackIntegrationService{}, &SlackIntegrationService{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(3)
	go func() { // startup installs the app
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			if i%2 == 0 {
				SetDefaultSlackService(a)
			} else {
				SetDefaultSlackService(b)
			}
		}
	}()
	for r := 0; r < 2; r++ { // requests read it
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 2000; i++ {
				if s := DefaultSlackService(); s != nil && s != a && s != b {
					t.Error("DefaultSlackService returned a service that was never set")
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	SetDefaultSlackService(a)
	if DefaultSlackService() != a {
		t.Fatal("DefaultSlackService does not return the service set last")
	}
}
