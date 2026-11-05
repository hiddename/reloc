package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// lockWait is how long a test waits to decide that a lock call is blocked.
const lockWait = 50 * time.Millisecond

func takeLock(t *testing.T, l *serverLocks, id int64) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := l.lock(ctx, id)
	if err != nil {
		t.Fatalf("lock(%d): %v", id, err)
	}
	return unlock
}

func TestServerLocksWaitForUnlock(t *testing.T) {
	var l serverLocks
	unlock := takeLock(t, &l, 1)

	got := make(chan func())
	go func() {
		next, err := l.lock(context.Background(), 1)
		if err != nil {
			t.Error(err)
		}
		got <- next
	}()

	select {
	case <-got:
		t.Fatal("second lock succeeded while the first one is held")
	case <-time.After(lockWait):
	}

	unlock()
	select {
	case next := <-got:
		next()
	case <-time.After(5 * time.Second):
		t.Fatal("second lock did not succeed after unlock")
	}
}

func TestServerLocksCanceled(t *testing.T) {
	var l serverLocks
	unlock := takeLock(t, &l, 1)
	defer unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.lock(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestServerLocksFreeAfterCanceledWait(t *testing.T) {
	var l serverLocks
	unlock := takeLock(t, &l, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.lock(ctx, 1); err == nil {
		t.Fatal("lock succeeded with a canceled context")
	}

	// the canceled wait must not have left the lock taken or released
	unlock()
	takeLock(t, &l, 1)()
}

func TestServerLocksIndependent(t *testing.T) {
	var l serverLocks
	unlock := takeLock(t, &l, 1)
	defer unlock()

	takeLock(t, &l, 2)()
}

func TestApplyServerNoAuth(t *testing.T) {
	a := New(nil) // the store must not be reached

	_, err := a.ApplyServer(context.Background(), 1)
	if !errors.Is(err, ErrNoAuth) {
		t.Errorf("err = %v, want ErrNoAuth", err)
	}
}

// A waiting apply must read the data only after it gets the lock, or it would
// overwrite a newer config with an older one. A missing server shows the order:
// a read before the lock would return "not found" instead of waiting.
func TestApplyServerReadsAfterLock(t *testing.T) {
	e := newTestEnv(t)
	a := NewAuth(e.app.store, ssh.Password("unused"))
	const missingServer = 1 << 62

	unlock := takeLock(t, &a.applyLocks, missingServer)
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()
	if _, err := a.ApplyServer(ctx, missingServer); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wait for the lock until the deadline", err)
	}
}
