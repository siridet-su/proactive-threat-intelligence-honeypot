package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func withBackupLock(ctx context.Context, cfg Config, operation func() error) error {
	if err := os.MkdirAll(cfg.BackupRoot, 0o700); err != nil {
		return fmt.Errorf("create backup lock directory: %w", err)
	}
	lockFile, err := os.OpenFile(filepath.Join(cfg.BackupRoot, ".backup.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open backup lock: %w", err)
	}
	defer lockFile.Close()

	for {
		err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("acquire backup lock: %w", err)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	return operation()
}
