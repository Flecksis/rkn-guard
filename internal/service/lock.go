package service

import (
	"fmt"
	"os"
	"syscall"
)

// AcquireLock serializes full/update/uninstall. Process exit releases the lock.
// Never unlink the lock file: waiters may still hold the old inode.
func AcquireLock() (*os.File, error) {
	f, err := os.OpenFile("/run/rkn-guard.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another rkn-guard operation is running: %w", err)
	}
	return f, nil
}
