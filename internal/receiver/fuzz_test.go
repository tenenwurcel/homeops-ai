package receiver

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func FuzzValidateArchivePath(f *testing.F) {
	for _, seed := range []string{
		"request.json", "snapshot.json", "vault/Note.md", "../escape", "/absolute", "vault/../escape", "vault\\escape", "vault//note", "vault/\u00c1 Evidence.md", "vault/control\nname.md",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		err := validateArchivePath(value)
		if err == nil {
			if value == "" || value[0] == '/' || bytes.ContainsRune([]byte(value), '\\') || !isPrintableASCII(value) {
				t.Fatalf("unsafe path accepted: %q", value)
			}
		}
	})
}

func isPrintableASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func FuzzCanonicalStatusDecoder(f *testing.F) {
	valid, _ := canonicalJSON(StatusRequest{1, Protocol, testRequestID, testPublisher, testCapability})
	f.Add(valid)
	f.Add([]byte("{}\n"))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var request StatusRequest
		err := decodeCanonical(data, &request)
		if err == nil {
			canonical, marshalErr := canonicalJSON(request)
			if marshalErr != nil || !bytes.Equal(data, canonical) {
				t.Fatal("decoder accepted a non-canonical frame")
			}
		}
	})
}

func FuzzSubmitArchive(f *testing.F) {
	manifest := []byte("{\"schema_version\":1}\n")
	manifestDigest := sha256.Sum256(manifest)
	request := SubmissionRequest{
		SchemaVersion: 1, Protocol: Protocol, RequestID: testRequestID,
		PublisherID: testPublisher, CapabilityToken: testCapability,
		ReleasePolicyID: strings.Repeat("d", 64),
		SnapshotID:      strings.Repeat("b", 64), SnapshotManifestSHA256: fmt.Sprintf("%x", manifestDigest),
	}
	requestData, _ := canonicalJSON(request)
	// The hand-built seeds exercise both framing and the archive parser; corpus
	// mutations must never escape the private staging directory or panic.
	f.Add(buildTarForFuzz([]tarEntry{
		{name: "request.json", body: requestData},
		{name: "snapshot.json", body: manifest},
		{name: "vault/Note.md", body: []byte("# Note\n")},
	}))
	f.Add([]byte("not a tar archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		environment := newTestEnvironment(t, func(config *Config) {
			config.MaxArchiveBytes = 1 << 20
			config.MaxExtractedBytes = 512 << 10
			config.MaxFileBytes = 256 << 10
			config.MaxFiles = 128
		})
		var output bytes.Buffer
		_ = environment.server.Run(CommandSubmit, "", bytes.NewReader(data), &output, &bytes.Buffer{})
		var response Response
		if json.Unmarshal(output.Bytes(), &response) != nil {
			t.Fatalf("receiver emitted an invalid JSON response: %q", output.Bytes())
		}
	})
}

func buildTarForFuzz(entries []tarEntry) []byte {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Size: int64(len(entry.body)), Typeflag: tar.TypeReg,
			Mode: 0o600, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0),
		}
		if writer.WriteHeader(header) != nil {
			return nil
		}
		if _, err := writer.Write(entry.body); err != nil {
			return nil
		}
	}
	if writer.Close() != nil {
		return nil
	}
	return output.Bytes()
}
