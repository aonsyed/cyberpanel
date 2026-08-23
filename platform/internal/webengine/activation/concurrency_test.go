package activation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type blockingStore struct {
	mu             sync.Mutex
	stageCalls     int
	firstStaged    chan struct{}
	secondStaged   chan struct{}
	releaseFirst   chan struct{}
	stagedReceipt  Receipt
	currentReceipt Receipt
}

func (store *blockingStore) Stage(context.Context, native.ConfigGeneration) (Receipt, error) {
	store.mu.Lock()
	store.stageCalls++
	call := store.stageCalls
	store.mu.Unlock()
	if call == 1 {
		close(store.firstStaged)
		<-store.releaseFirst
	}
	if call == 2 {
		close(store.secondStaged)
	}
	return store.stagedReceipt, nil
}

func (store *blockingStore) Current(context.Context) (Receipt, error) {
	return store.currentReceipt, nil
}

func (*blockingStore) SwapMaster(context.Context, Receipt) error    { return nil }
func (*blockingStore) RestoreMaster(context.Context, Receipt) error { return nil }
func (*blockingStore) Confirm(context.Context, Receipt) error       { return nil }

func TestApplySerializesConcurrentCallsOnOneActivator(t *testing.T) {
	generation := generation()
	staged := receipt(generation.Edition, generation.ContentDigest)
	store := &blockingStore{
		firstStaged:    make(chan struct{}),
		secondStaged:   make(chan struct{}),
		releaseFirst:   make(chan struct{}),
		stagedReceipt:  staged,
		currentReceipt: currentReceipt(staged.Edition, staged.Digest),
	}
	activator := &Activator{Store: store, Engine: &engineFake{}, Probe: &probeFake{}}
	results := make(chan error, 2)

	go func() {
		_, err := activator.Apply(context.Background(), generation)
		results <- err
	}()
	<-store.firstStaged
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		_, err := activator.Apply(context.Background(), generation)
		results <- err
	}()
	<-secondStarted

	secondEnteredBeforeRelease := false
	select {
	case <-store.secondStaged:
		secondEnteredBeforeRelease = true
	case <-time.After(200 * time.Millisecond):
	}
	close(store.releaseFirst)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
	}
	if secondEnteredBeforeRelease {
		t.Fatal("second Apply reached Store.Stage before the first Apply completed")
	}
}
