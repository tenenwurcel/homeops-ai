package receiver

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	Protocol            = "homeops.receiver/v1"
	CommandSubmit       = "homeops-receiver-v1 submit"
	CommandStatus       = "homeops-receiver-v1 status"
	CommandCommit       = "homeops-receiver-v1 commit"
	CommandCurrent      = "homeops-receiver-v1 current"
	defaultMaxArchive   = int64(64 << 20)
	defaultMaxExtracted = int64(32 << 20)
	defaultMaxFile      = int64(8 << 20)
	defaultMaxFiles     = 4096
	defaultMaxControl   = int64(16 << 10)
	defaultMaxResult    = int64(256 << 10)
	requestFileMax      = int64(64 << 10)
	snapshotManifestMax = int64(8 << 20)
	tarRecordSize       = int64(10 * 1024)
)

var publisherIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Config contains only server-controlled paths and resource limits. None of
// these values are accepted through the SSH protocol.
type Config struct {
	IncomingDir      string
	ResultsDir       string
	CommitsDir       string
	PublisherID      string
	ConsumerGroup    string
	ConsumerUser     string
	RequireRoot      bool
	CurrentStateFile string

	MaxArchiveBytes   int64
	MaxExtractedBytes int64
	MaxFileBytes      int64
	MaxFiles          int
	MaxControlBytes   int64
	MaxResultBytes    int64
}

func (c Config) withDefaults() Config {
	if c.MaxArchiveBytes == 0 {
		c.MaxArchiveBytes = defaultMaxArchive
	}
	if c.MaxExtractedBytes == 0 {
		c.MaxExtractedBytes = defaultMaxExtracted
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = defaultMaxFile
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = defaultMaxFiles
	}
	if c.MaxControlBytes == 0 {
		c.MaxControlBytes = defaultMaxControl
	}
	if c.MaxResultBytes == 0 {
		c.MaxResultBytes = defaultMaxResult
	}
	return c
}

func (c Config) validate() (Config, error) {
	c = c.withDefaults()
	if !publisherIDPattern.MatchString(c.PublisherID) {
		return Config{}, errors.New("publisher ID must match [a-z][a-z0-9-]{0,62}")
	}
	if c.RequireRoot && os.Geteuid() != 0 {
		return Config{}, errors.New("production receiver must run as root")
	}
	paths := []struct {
		name  string
		value string
	}{
		{"incoming directory", c.IncomingDir},
		{"results directory", c.ResultsDir},
		{"commits directory", c.CommitsDir},
	}
	seen := make(map[string]string, len(paths))
	for _, item := range paths {
		if item.value == "" || !filepath.IsAbs(item.value) {
			return Config{}, fmt.Errorf("%s must be an absolute path", item.name)
		}
		clean := filepath.Clean(item.value)
		if clean == string(filepath.Separator) {
			return Config{}, fmt.Errorf("%s may not be the filesystem root", item.name)
		}
		if previous, ok := seen[clean]; ok {
			return Config{}, fmt.Errorf("%s and %s must be distinct", previous, item.name)
		}
		seen[clean] = item.name
		info, err := os.Lstat(clean)
		if err != nil {
			return Config{}, fmt.Errorf("inspect %s: %w", item.name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return Config{}, fmt.Errorf("%s must be a real directory", item.name)
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return Config{}, fmt.Errorf("resolve %s: %w", item.name, err)
		}
		if resolved != clean {
			return Config{}, fmt.Errorf("%s may not contain symlink components", item.name)
		}
	}
	if c.CurrentStateFile == "" || !filepath.IsAbs(c.CurrentStateFile) {
		return Config{}, errors.New("current state file must be an absolute path")
	}
	c.CurrentStateFile = filepath.Clean(c.CurrentStateFile)
	stateParent := filepath.Dir(c.CurrentStateFile)
	stateInfo, err := os.Lstat(stateParent)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 || stateInfo.Mode().Perm()&0o027 != 0 {
		return Config{}, errors.New("current state parent must be a private real directory")
	}
	resolvedStateParent, err := filepath.EvalSymlinks(stateParent)
	if err != nil || resolvedStateParent != stateParent {
		return Config{}, errors.New("current state parent may not contain symlink components")
	}
	if c.MaxArchiveBytes <= 0 || c.MaxExtractedBytes <= 0 || c.MaxFileBytes <= 0 ||
		c.MaxFiles <= 0 || c.MaxControlBytes <= 0 || c.MaxResultBytes <= 0 {
		return Config{}, errors.New("all receiver limits must be positive")
	}
	if c.MaxFileBytes > c.MaxExtractedBytes {
		return Config{}, errors.New("maximum file size may not exceed maximum extracted size")
	}
	c.IncomingDir = strings.TrimSuffix(filepath.Clean(c.IncomingDir), string(filepath.Separator))
	c.ResultsDir = strings.TrimSuffix(filepath.Clean(c.ResultsDir), string(filepath.Separator))
	c.CommitsDir = strings.TrimSuffix(filepath.Clean(c.CommitsDir), string(filepath.Separator))
	return c, nil
}

func consumerIDs(userName, groupName string) (int, int, error) {
	if userName == "" && groupName == "" {
		return os.Geteuid(), os.Getegid(), nil
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("look up consumer user: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 0 {
		return 0, 0, errors.New("consumer user has invalid numeric UID")
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("look up consumer group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return 0, 0, errors.New("consumer group has invalid numeric GID")
	}
	return uid, gid, nil
}

func validateProductionOwnership(c Config, consumerUID, consumerGID int) error {
	for _, root := range []string{c.IncomingDir, c.CommitsDir} {
		info, err := os.Lstat(root)
		if err != nil {
			return err
		}
		uid, _, err := fileOwner(info)
		if err != nil || uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("receiver staging roots must be root-owned and not group/other writable")
		}
	}
	for _, expected := range []struct {
		path string
		uid  int
		gid  int
		mode os.FileMode
	}{
		{filepath.Join(c.IncomingDir, c.PublisherID), 0, consumerGID, 0o750},
		{filepath.Join(c.CommitsDir, c.PublisherID), 0, consumerGID, 0o750},
		{filepath.Join(c.ResultsDir, c.PublisherID), consumerUID, consumerGID, 0o750},
	} {
		info, err := os.Lstat(expected.path)
		if err != nil {
			return err
		}
		uid, gid, err := fileOwner(info)
		if err != nil || uid != expected.uid || gid != expected.gid || info.Mode().Perm() != expected.mode {
			return fmt.Errorf("production namespace has unsafe ownership or mode: %s", expected.path)
		}
	}
	stateParent := filepath.Dir(c.CurrentStateFile)
	info, err := os.Lstat(stateParent)
	if err != nil {
		return err
	}
	uid, _, err := fileOwner(info)
	if err != nil || uid != consumerUID || info.Mode().Perm()&0o022 != 0 {
		return errors.New("current-state parent must be consumer-owned and not group/other writable")
	}
	return nil
}

func fileOwner(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("filesystem does not expose Unix ownership")
	}
	return int(stat.Uid), int(stat.Gid), nil
}
