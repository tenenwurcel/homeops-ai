package receiver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func ensurePublisherDir(root, publisher string) (string, error) {
	path := filepath.Join(root, publisher)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("publisher namespace is not a real directory")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return "", errors.New("publisher namespace may not grant permissions to other users")
	}
	return path, nil
}

func randomSuffix() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	return writeExclusiveOwned(path, data, mode, -1)
}

func writeExclusiveOwned(path string, data []byte, mode os.FileMode, gid int) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if gid >= 0 && os.Geteuid() == 0 {
		if err := file.Chown(0, gid); err != nil {
			return err
		}
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// publishExclusiveOwned makes a fully written file visible in one link(2)
// operation and never overwrites an existing destination.
func publishExclusiveOwned(stagingRoot, namespace, name string, data []byte, mode os.FileMode, gid int) error {
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	temporary := filepath.Join(stagingRoot, ".commit-"+suffix+".partial")
	if err := writeExclusiveOwned(temporary, data, mode, gid); err != nil {
		return err
	}
	defer os.Remove(temporary)
	destination := filepath.Join(namespace, name)
	if err := os.Link(temporary, destination); err != nil {
		return err
	}
	if err := syncDirectory(namespace); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncDirectory(stagingRoot)
}

func preparePublishedTree(root string, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staging tree contains a symlink")
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(path, 0, gid); err != nil {
				return err
			}
		}
		mode := os.FileMode(0o640)
		if info.IsDir() {
			mode = 0o750
		} else if !info.Mode().IsRegular() {
			return errors.New("staging tree contains a special file")
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		item, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := item.Sync()
		closeErr := item.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func withNamespaceLock(namespace string, action func() error) error {
	fd, err := syscall.Open(namespace, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), namespace)
	defer lock.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("request publication is already in progress")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return action()
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target is not a regular file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("target exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("target exceeds size limit")
	}
	return data, nil
}

func readReceipt(path string, limit int64) (Receipt, []byte, error) {
	data, err := readBoundedRegular(path, limit)
	if err != nil {
		return Receipt{}, nil, err
	}
	var receipt Receipt
	if err := decodeCanonical(data, &receipt); err != nil {
		return Receipt{}, nil, fmt.Errorf("invalid receipt: %w", err)
	}
	return receipt, data, nil
}

func parseResultIdentity(data []byte) (resultIdentity, error) {
	var identity resultIdentity
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&identity); err != nil {
		return resultIdentity{}, fmt.Errorf("decode result: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return resultIdentity{}, errors.New("result contains trailing data")
	}
	return identity, nil
}
