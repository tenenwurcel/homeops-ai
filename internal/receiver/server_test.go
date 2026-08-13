package receiver

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testPublisher       = "workstation"
	testRequestID       = "123e4567-e89b-42d3-a456-426614174000"
	testCapability      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOldDeployment   = "1111111111111111111111111111111111111111111111111111111111111111"
	testNewDeployment   = "2222222222222222222222222222222222222222222222222222222222222222"
	testOtherDeployment = "3333333333333333333333333333333333333333333333333333333333333333"
)

type testEnvironment struct {
	server       *Server
	incomingRoot string
	incoming     string
	results      string
	commits      string
	current      string
}

func newTestEnvironment(t *testing.T, modify func(*Config)) testEnvironment {
	t.Helper()
	base := t.TempDir()
	roots := make([]string, 3)
	for index, name := range []string{"incoming", "results", "commits"} {
		root := filepath.Join(base, name)
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, testPublisher), 0o700); err != nil {
			t.Fatal(err)
		}
		roots[index] = root
	}
	config := Config{
		IncomingDir: roots[0], ResultsDir: roots[1], CommitsDir: roots[2], PublisherID: testPublisher,
	}
	stateDir := filepath.Join(base, "pipeline-state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config.CurrentStateFile = filepath.Join(stateDir, "current.json")
	if modify != nil {
		modify(&config)
	}
	server, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return testEnvironment{
		server:       server,
		incomingRoot: roots[0],
		incoming:     filepath.Join(roots[0], testPublisher),
		results:      filepath.Join(roots[1], testPublisher),
		commits:      filepath.Join(roots[2], testPublisher),
		current:      config.CurrentStateFile,
	}
}

func submissionFixture(t *testing.T, expected string) (SubmissionRequest, []byte) {
	t.Helper()
	manifest := []byte("{\"schema_version\":1}\n")
	manifestDigest := sha256.Sum256(manifest)
	request := SubmissionRequest{
		SchemaVersion:               1,
		Protocol:                    Protocol,
		RequestID:                   testRequestID,
		PublisherID:                 testPublisher,
		CapabilityToken:             testCapability,
		ReleasePolicyID:             strings.Repeat("d", 64),
		SnapshotID:                  strings.Repeat("b", 64),
		ExpectedCurrentDeploymentID: expected,
		SnapshotManifestSHA256:      fmt.Sprintf("%x", manifestDigest),
	}
	return request, manifest
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	mode     int64
	format   tar.Format
	linkname string
	uid      int
	mtime    time.Time
	pax      map[string]string
}

func validEntries(t *testing.T, note []byte, expected string) []tarEntry {
	t.Helper()
	request, manifest := submissionFixture(t, expected)
	requestData, err := canonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	return []tarEntry{
		{name: "request.json", body: requestData},
		{name: "snapshot.json", body: manifest},
		{name: "vault/Note.md", body: note},
	}
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		format := entry.format
		if format == tar.FormatUnknown {
			format = tar.FormatUSTAR
		}
		mtime := entry.mtime
		if mtime.IsZero() {
			mtime = time.Unix(0, 0)
		}
		header := &tar.Header{
			Name: entry.name, Size: int64(len(entry.body)), Typeflag: typeflag,
			Mode: mode, Format: format, Linkname: entry.linkname, Uid: entry.uid,
			ModTime: mtime, PAXRecords: entry.pax,
		}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%q): %v", entry.name, err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatalf("Write(%q): %v", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func runServer(t *testing.T, server *Server, command, tty string, input []byte) (int, Response, []byte) {
	t.Helper()
	var output bytes.Buffer
	code := server.Run(command, tty, bytes.NewReader(input), &output, &bytes.Buffer{})
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON (%q): %v", output.String(), err)
	}
	return code, response, output.Bytes()
}

func submitValid(t *testing.T, environment testEnvironment, expected string) Response {
	t.Helper()
	archive := buildTar(t, validEntries(t, []byte("# Note\n"), expected))
	code, response, _ := runServer(t, environment.server, CommandSubmit, "", archive)
	if code != 0 || response.Outcome != "ACCEPTED" {
		_, detail := environment.server.receiveArchive(bytes.NewReader(archive))
		t.Fatalf("submit = code %d, outcome %q: %v", code, response.Outcome, detail)
	}
	return response
}

func candidateResult(t *testing.T, environment testEnvironment, outcome string) map[string]any {
	t.Helper()
	return map[string]any{
		"schema_version":                 1,
		"protocol":                       Protocol,
		"request_id":                     testRequestID,
		"publisher_id":                   testPublisher,
		"outcome":                        outcome,
		"candidate_deployment_id":        testNewDeployment,
		"expected_current_deployment_id": testOldDeployment,
		"snapshot_id":                    strings.Repeat("b", 64),
		"run_id":                         testRequestID,
		"release_policy_id":              strings.Repeat("d", 64),
		"promotion_policy_id":            strings.Repeat("d", 64),
		"submission_archive_sha256":      submitArchiveHash(t, environment),
		"retryable":                      false,
	}
}

func TestSubmitStatusAndCapabilityBoundary(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	entries := validEntries(t, []byte("# Note\n"), testOldDeployment)
	wireRequest := append([]byte(nil), entries[0].body...)
	archive := buildTar(t, entries)
	code, submit, _ := runServer(t, environment.server, CommandSubmit, "", archive)
	if code != 0 || submit.Outcome != "ACCEPTED" {
		t.Fatalf("submit = code %d, outcome %q", code, submit.Outcome)
	}
	requestDir := filepath.Join(environment.incoming, testRequestID)
	if info, err := os.Lstat(requestDir); err != nil || !info.IsDir() {
		t.Fatalf("published request missing: %v", err)
	}
	receiptBytes, err := os.ReadFile(filepath.Join(requestDir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receiptBytes, []byte(testCapability)) {
		t.Fatal("receipt leaked raw capability")
	}
	queuedBytes, err := os.ReadFile(filepath.Join(requestDir, "payload", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(queuedBytes, []byte(testCapability)) {
		t.Fatal("queued request leaked raw capability")
	}
	var queued QueuedRequest
	if err := decodeCanonical(queuedBytes, &queued); err != nil {
		t.Fatalf("queued request is not canonical: %v", err)
	}
	if queued.RequestID != testRequestID || queued.ExpectedCurrentDeploymentID != testOldDeployment {
		t.Fatal("queued request lost submission identity")
	}
	var receipt Receipt
	if err := decodeCanonical(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ArchiveSHA256 != submit.ArchiveSHA256 || receipt.CapabilitySHA256 != capabilityDigest(testCapability) {
		t.Fatal("receipt does not bind archive and capability")
	}
	if receipt.ArchiveBytes != int64(len(archive)) || receipt.ExtractedBytes != int64(len(wireRequest)+len(entries[1].body)+len(entries[2].body)) {
		t.Fatal("receipt byte counts do not bind the wire archive")
	}
	expectedPaths := []string{"request.json", "snapshot.json", "vault/Note.md"}
	if len(receipt.Files) != len(expectedPaths) {
		t.Fatalf("receipt proof count = %d", len(receipt.Files))
	}
	if receipt.ReleasePolicyID != strings.Repeat("d", 64) {
		t.Fatal("receipt lost release policy identity")
	}
	for index, proof := range receipt.Files {
		if proof.Path != expectedPaths[index] {
			t.Fatalf("proof %d path = %q", index, proof.Path)
		}
	}
	wireDigest := sha256.Sum256(wireRequest)
	if receipt.Files[0].SHA256 != fmt.Sprintf("%x", wireDigest) || receipt.Files[0].Size != int64(len(wireRequest)) {
		t.Fatal("request proof does not bind original wire request")
	}
	if bytes.Equal(queuedBytes, wireRequest) {
		t.Fatal("queued request unexpectedly retained the wire capability")
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{requestDir, 0o750},
		{filepath.Join(requestDir, "payload"), 0o750},
		{filepath.Join(requestDir, "payload", "vault"), 0o750},
		{filepath.Join(requestDir, "receipt.json"), 0o640},
		{filepath.Join(requestDir, "payload", "request.json"), 0o640},
		{filepath.Join(requestDir, "payload", "snapshot.json"), 0o640},
		{filepath.Join(requestDir, "payload", "vault", "Note.md"), 0o640},
	} {
		info, statErr := os.Stat(item.path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", item.path, statErr)
		}
		if info.Mode().Perm() != item.mode {
			t.Fatalf("%s mode = %v, want %v", item.path, info.Mode().Perm(), item.mode)
		}
	}
	rootEntries, err := os.ReadDir(environment.incomingRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range rootEntries {
		if strings.HasPrefix(item.Name(), ".upload-") {
			t.Fatal("published request left a staging directory")
		}
	}

	wrong := StatusRequest{1, Protocol, testRequestID, testPublisher, strings.Repeat("c", 64)}
	wrongData, _ := canonicalJSON(wrong)
	code, response, raw := runServer(t, environment.server, CommandStatus, "", wrongData)
	if code == 0 || response.Outcome != "NOT_FOUND" || bytes.Contains(raw, []byte(testCapability)) {
		t.Fatalf("wrong capability = code %d, response %s", code, raw)
	}

	status := StatusRequest{1, Protocol, testRequestID, testPublisher, testCapability}
	statusData, _ := canonicalJSON(status)
	code, response, raw = runServer(t, environment.server, CommandStatus, "", statusData)
	if code != 0 || response.Outcome != "PENDING" || bytes.Contains(raw, []byte(testCapability)) {
		t.Fatalf("pending status = code %d, response %s", code, raw)
	}

	result := candidateResult(t, environment, "CANDIDATE_READY")
	result["diagnostic"] = "processor-only diagnostic"
	resultData, _ := canonicalJSON(result)
	if err := os.WriteFile(filepath.Join(environment.results, testRequestID+".json"), resultData, 0o600); err != nil {
		t.Fatal(err)
	}
	code, response, raw = runServer(t, environment.server, CommandStatus, "", statusData)
	if code != 0 || response.Outcome != "RESULT" || !bytes.Contains(response.Result, []byte("CANDIDATE_READY")) ||
		bytes.Contains(raw, []byte(testCapability)) || bytes.Contains(raw, []byte("processor-only diagnostic")) {
		t.Fatalf("ready status = code %d, response %s", code, raw)
	}
}

func TestStatusRejectsCapabilityInResult(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	submitValid(t, environment, "")
	result := fmt.Sprintf(`{"schema_version":1,"protocol":%q,"request_id":%q,"publisher_id":%q,"outcome":"FAILED","candidate_deployment_id":"","expected_current_deployment_id":"","detail":{"capability_token":%q}}`, Protocol, testRequestID, testPublisher, testCapability)
	if err := os.WriteFile(filepath.Join(environment.results, testRequestID+".json"), []byte(result+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _ := canonicalJSON(StatusRequest{1, Protocol, testRequestID, testPublisher, testCapability})
	code, response, raw := runServer(t, environment.server, CommandStatus, "", status)
	if code == 0 || response.Outcome != "INTERNAL_ERROR" || bytes.Contains(raw, []byte(testCapability)) {
		t.Fatalf("sensitive result = code %d, response %s", code, raw)
	}
}

func TestCommitIsReadyBoundAndIdempotent(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	submitValid(t, environment, testOldDeployment)
	commit := CommitRequest{1, Protocol, testRequestID, testPublisher, testCapability, testNewDeployment, testOldDeployment}
	commitData, _ := canonicalJSON(commit)
	code, response, _ := runServer(t, environment.server, CommandCommit, "", commitData)
	if code == 0 || response.Outcome != "COMMIT_NOT_READY" {
		t.Fatalf("early commit = code %d, outcome %q", code, response.Outcome)
	}

	ready := candidateResult(t, environment, "CANDIDATE_READY")
	readyData, _ := canonicalJSON(ready)
	if err := os.WriteFile(filepath.Join(environment.results, testRequestID+".json"), readyData, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := commit
	wrong.CandidateDeploymentID = testOtherDeployment
	wrongData, _ := canonicalJSON(wrong)
	code, response, _ = runServer(t, environment.server, CommandCommit, "", wrongData)
	if code == 0 || response.Outcome != "COMMIT_MISMATCH" {
		t.Fatalf("mismatched commit = code %d, outcome %q", code, response.Outcome)
	}

	code, response, raw := runServer(t, environment.server, CommandCommit, "", commitData)
	if code != 0 || response.Outcome != "COMMIT_ACCEPTED" || bytes.Contains(raw, []byte(testCapability)) {
		t.Fatalf("commit = code %d, response %s", code, raw)
	}
	marker, err := os.ReadFile(filepath.Join(environment.commits, testRequestID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(marker, []byte(testCapability)) || !bytes.Contains(marker, []byte(submitArchiveHash(t, environment))) {
		t.Fatal("commit marker leaked capability or omitted archive binding")
	}

	terminal := candidateResult(t, environment, "PROMOTED")
	terminalData, _ := canonicalJSON(terminal)
	if err := os.WriteFile(filepath.Join(environment.results, testRequestID+".json"), terminalData, 0o600); err != nil {
		t.Fatal(err)
	}
	code, response, _ = runServer(t, environment.server, CommandCommit, "", commitData)
	if code != 0 || response.Outcome != "COMMIT_ACCEPTED" || !response.Idempotent {
		t.Fatalf("idempotent commit = code %d, outcome %q", code, response.Outcome)
	}
}

func TestStatusReportsDurableCommitAcceptance(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	submitValid(t, environment, testOldDeployment)
	ready := candidateResult(t, environment, "CANDIDATE_READY")
	readyData, err := canonicalJSON(ready)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(environment.results, testRequestID+".json"), readyData, 0o600); err != nil {
		t.Fatal(err)
	}
	status := StatusRequest{
		SchemaVersion: 1, Protocol: Protocol, RequestID: testRequestID,
		PublisherID: testPublisher, CapabilityToken: testCapability,
	}
	statusData, _ := canonicalJSON(status)
	code, before, _ := runServer(t, environment.server, CommandStatus, "", statusData)
	if code != 0 || before.CommitAccepted == nil || *before.CommitAccepted {
		t.Fatalf("pre-commit status = code %d, accepted %v", code, before.CommitAccepted)
	}
	commit := CommitRequest{
		SchemaVersion: 1, Protocol: Protocol, RequestID: testRequestID,
		PublisherID: testPublisher, CapabilityToken: testCapability,
		CandidateDeploymentID:       testNewDeployment,
		ExpectedCurrentDeploymentID: testOldDeployment,
	}
	commitData, _ := canonicalJSON(commit)
	if code, response, _ := runServer(t, environment.server, CommandCommit, "", commitData); code != 0 || response.Outcome != "COMMIT_ACCEPTED" {
		t.Fatalf("commit = code %d, outcome %q", code, response.Outcome)
	}
	code, after, _ := runServer(t, environment.server, CommandStatus, "", statusData)
	if code != 0 || after.CommitAccepted == nil || !*after.CommitAccepted {
		t.Fatalf("post-commit status = code %d, accepted %v", code, after.CommitAccepted)
	}
}

func submitArchiveHash(t *testing.T, environment testEnvironment) string {
	t.Helper()
	receipt, _, err := readReceipt(filepath.Join(environment.incoming, testRequestID, "receipt.json"), defaultMaxResult)
	if err != nil {
		t.Fatal(err)
	}
	return receipt.ArchiveSHA256
}

func TestSubmitIdempotencyAndConflict(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	firstArchive := buildTar(t, validEntries(t, []byte("first"), ""))
	code, response, _ := runServer(t, environment.server, CommandSubmit, "", firstArchive)
	if code != 0 || response.Idempotent {
		t.Fatalf("first submit = code %d idempotent %v", code, response.Idempotent)
	}
	code, response, _ = runServer(t, environment.server, CommandSubmit, "", firstArchive)
	if code != 0 || !response.Idempotent {
		t.Fatalf("repeat submit = code %d idempotent %v", code, response.Idempotent)
	}
	secondArchive := buildTar(t, validEntries(t, []byte("different"), ""))
	code, response, _ = runServer(t, environment.server, CommandSubmit, "", secondArchive)
	if code == 0 || response.Outcome != "REQUEST_ID_CONFLICT" {
		t.Fatalf("conflict submit = code %d outcome %q", code, response.Outcome)
	}
}

func TestForcedCommandAndControlFraming(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	for _, test := range []struct {
		command string
		tty     string
	}{
		{"", ""},
		{"bash", ""},
		{CommandStatus + " " + testRequestID, ""},
		{"scp -t /tmp/file", ""},
		{CommandSubmit, "/dev/pts/1"},
	} {
		code, response, _ := runServer(t, environment.server, test.command, test.tty, nil)
		if code == 0 || response.Outcome != "PROTOCOL_REJECTED" {
			t.Fatalf("command %q tty %q was accepted", test.command, test.tty)
		}
	}

	status := StatusRequest{1, Protocol, testRequestID, testPublisher, testCapability}
	canonical, _ := canonicalJSON(status)
	frames := [][]byte{
		bytes.TrimSuffix(canonical, []byte("\n")),
		append([]byte(" "), canonical...),
		append(bytes.TrimSuffix(canonical, []byte("\n")), []byte(" \n")...),
		[]byte(`{"schema_version":1,"protocol":"homeops.receiver/v1","request_id":"123e4567-e89b-42d3-a456-426614174000","publisher_id":"workstation","capability_token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}` + "\n"),
	}
	for _, frame := range frames {
		code, response, _ := runServer(t, environment.server, CommandStatus, "", frame)
		if code == 0 || response.Outcome != "INVALID_REQUEST" {
			t.Fatalf("non-canonical control frame was accepted: %q", frame)
		}
	}
}

func TestCurrentState(t *testing.T) {
	environment := newTestEnvironment(t, nil)
	code, response, raw := runServer(t, environment.server, CommandCurrent, "", nil)
	if code == 0 || response.Outcome != "INTERNAL_ERROR" {
		t.Fatalf("missing current = code %d response %s", code, raw)
	}
	emptyData, _ := canonicalJSON(CurrentState{SchemaVersion: 2})
	if err := os.WriteFile(environment.current, emptyData, 0o600); err != nil {
		t.Fatal(err)
	}
	code, response, raw = runServer(t, environment.server, CommandCurrent, "", nil)
	if code != 0 || response.Outcome != "CURRENT" || len(response.Current) == 0 {
		t.Fatalf("bootstrap current = code %d response %s", code, raw)
	}
	var empty CurrentState
	if err := json.Unmarshal(response.Current, &empty); err != nil || empty.SchemaVersion != 2 || empty.CurrentDeploymentID != "" {
		t.Fatalf("invalid empty state: %s", response.Current)
	}
	state := CurrentState{
		SchemaVersion: 2, CurrentDeploymentID: strings.Repeat("a", 64), SnapshotID: strings.Repeat("b", 64),
		RunID: testRequestID, SourceFingerprint: strings.Repeat("c", 64), ArtifactFingerprint: strings.Repeat("d", 64),
		LogicalFingerprint: strings.Repeat("e", 64), HomeOpsVersion: "0.4.0", SourceRevision: "abc123",
		ImageDigest: "sha256:" + strings.Repeat("f", 64), SnapshotContractVersion: "homeops-snapshot-v1",
		BuildContractVersion: "homeops-build-v1", PromotedAt: "2026-08-13T12:34:56Z",
	}
	stateData, _ := canonicalJSON(state)
	if err := os.WriteFile(environment.current, stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	code, response, raw = runServer(t, environment.server, CommandCurrent, "", nil)
	if code != 0 || response.Outcome != "CURRENT" || !bytes.Equal(response.Current, bytes.TrimSpace(stateData)) {
		t.Fatalf("current = code %d response %s", code, raw)
	}
	expectedEnvelope, _ := canonicalJSON(CurrentResponse{
		SchemaVersion: 1, Protocol: Protocol, Outcome: "CURRENT", Current: json.RawMessage(stateData),
	})
	if !bytes.Equal(raw, expectedEnvelope) {
		t.Fatalf("current envelope is not exact canonical framing:\n got %s\nwant %s", raw, expectedEnvelope)
	}
	code, response, _ = runServer(t, environment.server, CommandCurrent, "", []byte("x"))
	if code == 0 || response.Outcome != "INVALID_REQUEST" {
		t.Fatal("current accepted nonempty stdin")
	}
	state.RunID = ""
	partial, _ := canonicalJSON(state)
	if err := os.WriteFile(environment.current, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	code, response, _ = runServer(t, environment.server, CommandCurrent, "", nil)
	if code == 0 || response.Outcome != "INTERNAL_ERROR" {
		t.Fatal("current accepted partial state")
	}
}

func TestArchiveRejectsUnsafeEntriesAndMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]tarEntry) []tarEntry
	}{
		{"path traversal", func(entries []tarEntry) []tarEntry { entries[2].name = "vault/../escape"; return entries }},
		{"absolute path", func(entries []tarEntry) []tarEntry { entries[2].name = "/tmp/escape"; return entries }},
		{"backslash", func(entries []tarEntry) []tarEntry { entries[2].name = `vault\escape`; return entries }},
		{"symlink", func(entries []tarEntry) []tarEntry {
			entries[2].typeflag = tar.TypeSymlink
			entries[2].linkname = "/tmp"
			return entries
		}},
		{"hardlink", func(entries []tarEntry) []tarEntry {
			entries[2].typeflag = tar.TypeLink
			entries[2].linkname = "request.json"
			return entries
		}},
		{"directory", func(entries []tarEntry) []tarEntry { entries[2].typeflag = tar.TypeDir; return entries }},
		{"device", func(entries []tarEntry) []tarEntry { entries[2].typeflag = tar.TypeChar; return entries }},
		{"fifo", func(entries []tarEntry) []tarEntry { entries[2].typeflag = tar.TypeFifo; return entries }},
		{"duplicate", func(entries []tarEntry) []tarEntry { return append(entries, entries[2]) }},
		{"unsorted", func(entries []tarEntry) []tarEntry {
			entries = append(entries, tarEntry{name: "vault/A.md", body: []byte("x")})
			return entries
		}},
		{"undeclared root", func(entries []tarEntry) []tarEntry { entries[2].name = "unexpected.json"; return entries }},
		{"noncanonical mode", func(entries []tarEntry) []tarEntry { entries[2].mode = 0o644; return entries }},
		{"noncanonical owner", func(entries []tarEntry) []tarEntry { entries[2].uid = 1000; return entries }},
		{"noncanonical time", func(entries []tarEntry) []tarEntry { entries[2].mtime = time.Unix(1, 0); return entries }},
		{"pax", func(entries []tarEntry) []tarEntry {
			entries[2].format = tar.FormatPAX
			entries[2].pax = map[string]string{"comment": "prohibited"}
			return entries
		}},
		{"gnu", func(entries []tarEntry) []tarEntry { entries[2].format = tar.FormatGNU; return entries }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, nil)
			archive := buildTar(t, test.mutate(validEntries(t, []byte("note"), "")))
			code, response, _ := runServer(t, environment.server, CommandSubmit, "", archive)
			if code == 0 || response.Outcome != "ARCHIVE_INVALID" {
				t.Fatalf("unsafe archive = code %d, outcome %q", code, response.Outcome)
			}
			if _, err := os.Stat(filepath.Join(environment.incoming, testRequestID)); !os.IsNotExist(err) {
				t.Fatal("invalid archive published a request")
			}
		})
	}
}

func TestArchiveLimitsAndManifestBinding(t *testing.T) {
	t.Run("file size", func(t *testing.T) {
		environment := newTestEnvironment(t, func(config *Config) { config.MaxFileBytes = 1024 })
		entries := validEntries(t, bytes.Repeat([]byte("x"), 1025), "")
		code, response, _ := runServer(t, environment.server, CommandSubmit, "", buildTar(t, entries))
		if code == 0 || response.Outcome != "ARCHIVE_LIMIT_EXCEEDED" {
			t.Fatalf("file limit = code %d, outcome %q", code, response.Outcome)
		}
	})
	t.Run("file count", func(t *testing.T) {
		environment := newTestEnvironment(t, func(config *Config) { config.MaxFiles = 2 })
		code, response, _ := runServer(t, environment.server, CommandSubmit, "", buildTar(t, validEntries(t, []byte("x"), "")))
		if code == 0 || response.Outcome != "ARCHIVE_LIMIT_EXCEEDED" {
			t.Fatalf("file count = code %d, outcome %q", code, response.Outcome)
		}
	})
	t.Run("manifest mismatch", func(t *testing.T) {
		environment := newTestEnvironment(t, nil)
		entries := validEntries(t, []byte("x"), "")
		request, _ := submissionFixture(t, "")
		request.SnapshotManifestSHA256 = strings.Repeat("f", 64)
		entries[0].body, _ = canonicalJSON(request)
		code, response, _ := runServer(t, environment.server, CommandSubmit, "", buildTar(t, entries))
		if code == 0 || response.Outcome != "ARCHIVE_INVALID" {
			t.Fatalf("manifest mismatch = code %d, outcome %q", code, response.Outcome)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		environment := newTestEnvironment(t, nil)
		archive := buildTar(t, validEntries(t, []byte("x"), ""))
		archive = archive[:len(archive)-700]
		code, response, _ := runServer(t, environment.server, CommandSubmit, "", archive)
		if code == 0 || response.Outcome != "ARCHIVE_INVALID" {
			t.Fatalf("truncated = code %d, outcome %q", code, response.Outcome)
		}
	})
}

func TestPythonTarfileStreamingArchiveInterop(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	request, manifest := submissionFixture(t, testOldDeployment)
	requestData, _ := canonicalJSON(request)
	script := `
import io, json, sys, tarfile
parts = json.load(sys.stdin)
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
    for name, value in parts:
        data = bytes.fromhex(value)
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o600
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        archive.addfile(info, io.BytesIO(data))
`
	parts := [][]string{
		{"request.json", fmt.Sprintf("%x", requestData)},
		{"snapshot.json", fmt.Sprintf("%x", manifest)},
		{"vault/Note.md", fmt.Sprintf("%x", []byte("# Note\n"))},
	}
	input, _ := json.Marshal(parts)
	command := exec.Command(python, "-c", script)
	command.Stdin = bytes.NewReader(input)
	archive, err := command.Output()
	if err != nil {
		t.Fatalf("python tar fixture: %v", err)
	}
	if len(archive)%int(tarRecordSize) != 0 {
		t.Fatalf("Python archive has unexpected blocking: %d", len(archive))
	}
	environment := newTestEnvironment(t, nil)
	code, response, _ := runServer(t, environment.server, CommandSubmit, "", archive)
	if code != 0 || response.Outcome != "ACCEPTED" {
		t.Fatalf("Python archive = code %d, outcome %q", code, response.Outcome)
	}

	environment = newTestEnvironment(t, nil)
	archive[len(archive)-1] = 1
	code, response, _ = runServer(t, environment.server, CommandSubmit, "", archive)
	if code == 0 || response.Outcome != "ARCHIVE_INVALID" {
		t.Fatalf("nonzero Python padding = code %d, outcome %q", code, response.Outcome)
	}
}

func TestHomeOpsPythonWriterAndCurrentProjectionInterop(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repository, ".venv", "bin", "python")
	if _, err := os.Stat(python); err != nil {
		t.Skip("project Python environment is unavailable")
	}
	environment := newTestEnvironment(t, nil)
	remoteRoot := filepath.Dir(filepath.Dir(environment.current))
	sourceRoot := filepath.Join(t.TempDir(), "source")
	snapshotRoot := filepath.Join(t.TempDir(), "snapshot")
	script := `
import sys
from pathlib import Path
from homeops_ai.build import inspect_vault
from homeops_ai.deployment import (
    create_deployment_record, empty_state, publish_current_projection,
    select_deployment,
)
from homeops_ai.snapshot import (
    RECEIVER_PROTOCOL, RECEIVER_SCHEMA_VERSION, create_snapshot_manifest,
    file_sha256, submission_archive_bytes, write_manifest,
)
from homeops_ai.source_contract import export_snapshot

source, snapshot, remote = map(Path, sys.argv[1:])
(source / "Categories").mkdir(parents=True)
(source / "Categories" / "AI.md").write_text("""---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
""", encoding="utf-8")
for name, note_id in (
    ("AI Context.md", "11111111-1111-4111-8111-111111111111"),
    ("a lowercase.md", "22222222-2222-4222-8222-222222222222"),
    ("Z Uppercase.md", "33333333-3333-4333-8333-333333333333"),
):
    (source / name).write_text(f"""---
id: "{note_id}"
categories: ["[[AI]]"]
type: current-state
status: current
authority: canonical
---
Evidence.
""", encoding="utf-8")
(source / "artifact.bin").write_bytes(b"not exported")
export_snapshot(source, snapshot)
inspection = inspect_vault(snapshot)
manifest = create_snapshot_manifest(
    snapshot, inspection, created_at="2026-08-13T12:00:00+00:00",
    package_version="0.4.0-test", source_revision="test-revision",
)
manifest_path = snapshot.parent / "snapshot.json"
write_manifest(manifest_path, manifest)
request = {
    "schema_version": RECEIVER_SCHEMA_VERSION,
    "protocol": RECEIVER_PROTOCOL,
    "request_id": "123e4567-e89b-42d3-a456-426614174000",
    "publisher_id": "workstation",
    "capability_token": "a" * 64,
    "release_policy_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "snapshot_id": manifest["snapshot_id"],
    "expected_current_deployment_id": "",
    "snapshot_manifest_sha256": file_sha256(manifest_path),
}
fingerprint = "c" * 64
record = create_deployment_record(
    snapshot={
        "schema_version": 1,
        "snapshot_contract_version": "homeops-snapshot-v1",
        "snapshot_id": "b" * 64,
        "created_at": "2026-08-13T12:00:00Z",
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
    },
    build={
        "schema_version": 1,
        "build_contract_version": "homeops-build-v1",
        "run_id": "123e4567-e89b-42d3-a456-426614174000",
        "completed_at": "2026-08-13T12:01:00Z",
        "verified_at": "2026-08-13T12:02:00Z",
        "result": "verified",
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
    },
    snapshot_received_at="2026-08-13T12:00:30Z",
    homeops_version="0.4.0-test",
    source_revision="feature/test+dirty",
    image_digest="ghcr.io/example/homeops@sha256:" + "d" * 64,
)
state, _ = select_deployment(
    empty_state(), record, expected_current_deployment_id=None,
    promoted_at="2026-08-13T12:03:00Z",
)
publish_current_projection(remote, state)
sys.stdout.buffer.write(submission_archive_bytes(request, manifest, snapshot))
`
	command := exec.Command(python, "-c", script, sourceRoot, snapshotRoot, remoteRoot)
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repository, "src"))
	archive, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			t.Fatalf("HomeOps Python fixture: %v\n%s", err, exit.Stderr)
		}
		t.Fatal(err)
	}
	code, response, raw := runServer(t, environment.server, CommandSubmit, "", archive)
	if code != 0 || response.Outcome != "ACCEPTED" {
		_, detail := environment.server.receiveArchive(bytes.NewReader(archive))
		t.Fatalf("HomeOps Python archive = code %d, response %s: %v", code, raw, detail)
	}
	code, response, raw = runServer(t, environment.server, CommandCurrent, "", nil)
	if code != 0 || response.Outcome != "CURRENT" {
		t.Fatalf("HomeOps Python current projection = code %d, response %s", code, raw)
	}
}

func TestNewRejectsUnsafeNamespaces(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"incoming", "results", "commits"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(base, name, testPublisher), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(base, "incoming", testPublisher), 0o707); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		IncomingDir: filepath.Join(base, "incoming"), ResultsDir: filepath.Join(base, "results"),
		CommitsDir: filepath.Join(base, "commits"), PublisherID: testPublisher,
		CurrentStateFile: filepath.Join(base, "results", "current.json"),
	})
	if err == nil {
		t.Fatal("world-accessible namespace was accepted")
	}
}
