package receiver

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	errArchiveInvalid  = errors.New("archive is invalid")
	errArchiveLimit    = errors.New("archive exceeds a configured limit")
	errRequestConflict = errors.New("request ID was already used for different bytes")
)

type meteredReader struct {
	reader io.Reader
	hash   hash.Hash
	count  int64
}

func (r *meteredReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		_, _ = r.hash.Write(buffer[:n])
		r.count += int64(n)
	}
	return n, err
}

type archiveResult struct {
	receipt    Receipt
	idempotent bool
}

func (s *Server) receiveArchive(input io.Reader) (result archiveResult, returnedErr error) {
	namespace := s.incomingNamespace
	suffix, err := randomSuffix()
	if err != nil {
		return archiveResult{}, fmt.Errorf("create staging identifier: %w", err)
	}
	// Stage outside the processor-watched publisher namespace. Only the final
	// atomic rename makes a directory discoverable as a request.
	staging := filepath.Join(s.config.IncomingDir, ".upload-"+s.config.PublisherID+"-"+suffix)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return archiveResult{}, fmt.Errorf("create private staging directory: %w", err)
	}
	defer func() {
		if returnedErr != nil || result.idempotent {
			_ = os.RemoveAll(staging)
		}
	}()
	payload := filepath.Join(staging, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		return archiveResult{}, fmt.Errorf("create payload directory: %w", err)
	}

	limited := &io.LimitedReader{R: input, N: s.config.MaxArchiveBytes + 1}
	meter := &meteredReader{reader: limited, hash: sha256.New()}
	archive := tar.NewReader(meter)
	var (
		request        SubmissionRequest
		previousPath   string
		extractedBytes int64
		fileCount      int
		vaultFileCount int
		proofs         []FileProof
		manifestHash   string
		canonicalBytes int64 = 1024 // two required USTAR end-marker blocks
	)

	for {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return archiveResult{}, fmt.Errorf("%w: unreadable tar stream", errArchiveInvalid)
		}
		fileCount++
		if fileCount > s.config.MaxFiles {
			return archiveResult{}, fmt.Errorf("%w: too many files", errArchiveLimit)
		}
		if err := validateArchiveHeader(header, fileCount, previousPath); err != nil {
			return archiveResult{}, err
		}
		previousPath = header.Name
		canonicalBytes += 512 + ((header.Size+511)/512)*512
		if header.Size > s.config.MaxFileBytes || header.Size > perPathLimit(header.Name) {
			return archiveResult{}, fmt.Errorf("%w: file is too large", errArchiveLimit)
		}
		if header.Size > s.config.MaxExtractedBytes-extractedBytes {
			return archiveResult{}, fmt.Errorf("%w: extracted data is too large", errArchiveLimit)
		}

		fileHash := sha256.New()
		var (
			body    []byte
			written int64
			copyErr error
		)
		if header.Name == "request.json" {
			body, copyErr = io.ReadAll(io.TeeReader(io.LimitReader(archive, header.Size), fileHash))
			written = int64(len(body))
		} else {
			target := filepath.Join(payload, filepath.FromSlash(header.Name))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return archiveResult{}, fmt.Errorf("create payload parent: %w", err)
			}
			output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return archiveResult{}, fmt.Errorf("create payload file: %w", err)
			}
			written, copyErr = io.CopyN(io.MultiWriter(output, fileHash), archive, header.Size)
			syncErr := output.Sync()
			closeErr := output.Close()
			if syncErr != nil {
				return archiveResult{}, fmt.Errorf("flush payload file: %w", syncErr)
			}
			if closeErr != nil {
				return archiveResult{}, fmt.Errorf("close payload file: %w", closeErr)
			}
		}
		if copyErr != nil || written != header.Size {
			return archiveResult{}, fmt.Errorf("%w: truncated file body", errArchiveInvalid)
		}

		digest := hex.EncodeToString(fileHash.Sum(nil))
		proofs = append(proofs, FileProof{Path: header.Name, Size: header.Size, SHA256: digest})
		extractedBytes += header.Size
		switch header.Name {
		case "request.json":
			if err := decodeCanonical(body, &request); err != nil {
				return archiveResult{}, fmt.Errorf("%w: invalid request JSON", errArchiveInvalid)
			}
			if err := request.validate(s.config.PublisherID); err != nil {
				return archiveResult{}, fmt.Errorf("%w: invalid request identity", errArchiveInvalid)
			}
			sanitized, err := canonicalJSON(request.queued())
			if err != nil {
				return archiveResult{}, fmt.Errorf("persist sanitized request: %w", err)
			}
			if err := writeExclusive(filepath.Join(payload, "request.json"), sanitized, 0o600); err != nil {
				return archiveResult{}, fmt.Errorf("persist sanitized request: %w", err)
			}
		case "snapshot.json":
			manifestHash = digest
		default:
			vaultFileCount++
		}
	}

	// Python's tarfile streaming writer uses the conventional 10 KiB USTAR
	// blocking factor. Accept only zero bytes needed to reach that boundary;
	// this rejects concatenated archives and arbitrary trailing data.
	endMarkerBytes := meter.count
	extra, err := io.ReadAll(meter)
	if err != nil {
		return archiveResult{}, fmt.Errorf("%w: read archive trailer", errArchiveInvalid)
	}
	if meter.count > s.config.MaxArchiveBytes {
		return archiveResult{}, fmt.Errorf("%w: archive is too large", errArchiveLimit)
	}
	if endMarkerBytes != canonicalBytes {
		return archiveResult{}, fmt.Errorf("%w: missing or non-canonical USTAR end marker", errArchiveInvalid)
	}
	expectedPadding := int((tarRecordSize - (endMarkerBytes % tarRecordSize)) % tarRecordSize)
	if (len(extra) != 0 && len(extra) != expectedPadding) || !allZero(extra) {
		return archiveResult{}, fmt.Errorf("%w: trailing archive bytes (marker=%d tail=%d expected=%d zero=%t)", errArchiveInvalid, endMarkerBytes, len(extra), expectedPadding, allZero(extra))
	}
	if fileCount < 3 || vaultFileCount == 0 || request.RequestID == "" || manifestHash == "" {
		return archiveResult{}, fmt.Errorf("%w: required archive entries are missing", errArchiveInvalid)
	}
	if manifestHash != request.SnapshotManifestSHA256 {
		return archiveResult{}, fmt.Errorf("%w: snapshot manifest hash mismatch", errArchiveInvalid)
	}

	receipt := Receipt{
		SchemaVersion:               1,
		Protocol:                    Protocol,
		RequestID:                   request.RequestID,
		PublisherID:                 request.PublisherID,
		CapabilitySHA256:            capabilityDigest(request.CapabilityToken),
		ReleasePolicyID:             request.ReleasePolicyID,
		SnapshotID:                  request.SnapshotID,
		ExpectedCurrentDeploymentID: request.ExpectedCurrentDeploymentID,
		SnapshotManifestSHA256:      request.SnapshotManifestSHA256,
		ArchiveSHA256:               hex.EncodeToString(meter.hash.Sum(nil)),
		ArchiveBytes:                meter.count,
		ExtractedBytes:              extractedBytes,
		FileCount:                   fileCount,
		VaultFileCount:              vaultFileCount,
		Files:                       proofs,
	}
	receiptData, err := canonicalJSON(receipt)
	if err != nil {
		return archiveResult{}, err
	}
	if err := writeExclusive(filepath.Join(staging, "receipt.json"), receiptData, 0o600); err != nil {
		return archiveResult{}, fmt.Errorf("write receipt: %w", err)
	}
	if err := syncDirectory(payload); err != nil {
		return archiveResult{}, fmt.Errorf("flush payload directory: %w", err)
	}
	if err := syncDirectory(staging); err != nil {
		return archiveResult{}, fmt.Errorf("flush staging directory: %w", err)
	}
	if err := preparePublishedTree(staging, s.consumerGID); err != nil {
		return archiveResult{}, fmt.Errorf("seal request for processor: %w", err)
	}

	destination := filepath.Join(namespace, request.RequestID)
	publishResult := archiveResult{receipt: receipt}
	err = withNamespaceLock(s.config.IncomingDir, func() error {
		if pathExists(destination) {
			existingInfo, statErr := os.Lstat(destination)
			if statErr != nil || !existingInfo.IsDir() || existingInfo.Mode()&os.ModeSymlink != 0 {
				return errRequestConflict
			}
			existing, _, receiptErr := readReceipt(filepath.Join(destination, "receipt.json"), s.config.MaxResultBytes)
			if receiptErr != nil || existing.RequestID != request.RequestID || existing.PublisherID != s.config.PublisherID {
				return errRequestConflict
			}
			if existing.ArchiveSHA256 != receipt.ArchiveSHA256 || existing.ArchiveBytes != receipt.ArchiveBytes {
				return errRequestConflict
			}
			publishResult = archiveResult{receipt: existing, idempotent: true}
			return nil
		}
		if err := os.Rename(staging, destination); err != nil {
			return fmt.Errorf("publish request: %w", err)
		}
		return syncDirectory(namespace)
	})
	if err != nil {
		return archiveResult{}, err
	}
	return publishResult, nil
}

func perPathLimit(name string) int64 {
	switch name {
	case "request.json":
		return requestFileMax
	case "snapshot.json":
		return snapshotManifestMax
	default:
		return int64(^uint64(0) >> 1)
	}
}

func validateArchiveHeader(header *tar.Header, index int, previous string) error {
	if header.Format != tar.FormatUSTAR {
		return fmt.Errorf("%w: only USTAR is accepted (format=%v path=%q)", errArchiveInvalid, header.Format, header.Name)
	}
	if header.Typeflag != tar.TypeReg || header.Linkname != "" {
		return fmt.Errorf("%w: only regular files are accepted", errArchiveInvalid)
	}
	if header.Mode != 0o600 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
		return fmt.Errorf("%w: non-canonical file metadata", errArchiveInvalid)
	}
	if !header.ModTime.Equal(time.Unix(0, 0)) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
		return fmt.Errorf("%w: non-canonical timestamps", errArchiveInvalid)
	}
	if header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return fmt.Errorf("%w: extended metadata is prohibited", errArchiveInvalid)
	}
	if err := validateArchivePath(header.Name); err != nil {
		return err
	}
	if previous != "" && strings.Compare(previous, header.Name) >= 0 {
		return fmt.Errorf("%w: paths must be unique and strictly sorted", errArchiveInvalid)
	}
	switch index {
	case 1:
		if header.Name != "request.json" {
			return fmt.Errorf("%w: request.json must be first", errArchiveInvalid)
		}
	case 2:
		if header.Name != "snapshot.json" {
			return fmt.Errorf("%w: snapshot.json must be second", errArchiveInvalid)
		}
	default:
		if !strings.HasPrefix(header.Name, "vault/") || header.Name == "vault/" {
			return fmt.Errorf("%w: undeclared top-level path", errArchiveInvalid)
		}
	}
	return nil
}

func validateArchivePath(name string) error {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) {
		return fmt.Errorf("%w: invalid path encoding", errArchiveInvalid)
	}
	for _, value := range []byte(name) {
		if value < 0x20 || value > 0x7e {
			return fmt.Errorf("%w: path must contain printable ASCII only", errArchiveInvalid)
		}
	}
	if strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return fmt.Errorf("%w: non-canonical path", errArchiveInvalid)
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("%w: unsafe path component", errArchiveInvalid)
		}
	}
	return nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func allZero(data []byte) bool {
	var combined byte
	for _, value := range data {
		combined |= value
	}
	return combined == 0
}
