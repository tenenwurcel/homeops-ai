package receiver

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

var (
	uuidV4Pattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$`)
)

type SubmissionRequest struct {
	SchemaVersion               int    `json:"schema_version"`
	Protocol                    string `json:"protocol"`
	RequestID                   string `json:"request_id"`
	PublisherID                 string `json:"publisher_id"`
	CapabilityToken             string `json:"capability_token"`
	ReleasePolicyID             string `json:"release_policy_id"`
	SnapshotID                  string `json:"snapshot_id"`
	ExpectedCurrentDeploymentID string `json:"expected_current_deployment_id"`
	SnapshotManifestSHA256      string `json:"snapshot_manifest_sha256"`
}

// QueuedRequest is the capability-free request metadata visible to the remote
// processor. The raw capability is never persisted; Receipt contains only its
// SHA-256 digest.
type QueuedRequest struct {
	SchemaVersion               int    `json:"schema_version"`
	Protocol                    string `json:"protocol"`
	RequestID                   string `json:"request_id"`
	PublisherID                 string `json:"publisher_id"`
	ReleasePolicyID             string `json:"release_policy_id"`
	SnapshotID                  string `json:"snapshot_id"`
	ExpectedCurrentDeploymentID string `json:"expected_current_deployment_id"`
	SnapshotManifestSHA256      string `json:"snapshot_manifest_sha256"`
}

func (r SubmissionRequest) queued() QueuedRequest {
	return QueuedRequest{
		SchemaVersion:               r.SchemaVersion,
		Protocol:                    r.Protocol,
		RequestID:                   r.RequestID,
		PublisherID:                 r.PublisherID,
		ReleasePolicyID:             r.ReleasePolicyID,
		SnapshotID:                  r.SnapshotID,
		ExpectedCurrentDeploymentID: r.ExpectedCurrentDeploymentID,
		SnapshotManifestSHA256:      r.SnapshotManifestSHA256,
	}
}

type StatusRequest struct {
	SchemaVersion   int    `json:"schema_version"`
	Protocol        string `json:"protocol"`
	RequestID       string `json:"request_id"`
	PublisherID     string `json:"publisher_id"`
	CapabilityToken string `json:"capability_token"`
}

type CommitRequest struct {
	SchemaVersion               int    `json:"schema_version"`
	Protocol                    string `json:"protocol"`
	RequestID                   string `json:"request_id"`
	PublisherID                 string `json:"publisher_id"`
	CapabilityToken             string `json:"capability_token"`
	CandidateDeploymentID       string `json:"candidate_deployment_id"`
	ExpectedCurrentDeploymentID string `json:"expected_current_deployment_id"`
}

type Receipt struct {
	SchemaVersion               int         `json:"schema_version"`
	Protocol                    string      `json:"protocol"`
	RequestID                   string      `json:"request_id"`
	PublisherID                 string      `json:"publisher_id"`
	CapabilitySHA256            string      `json:"capability_sha256"`
	ReleasePolicyID             string      `json:"release_policy_id"`
	SnapshotID                  string      `json:"snapshot_id"`
	ExpectedCurrentDeploymentID string      `json:"expected_current_deployment_id"`
	SnapshotManifestSHA256      string      `json:"snapshot_manifest_sha256"`
	ArchiveSHA256               string      `json:"archive_sha256"`
	ArchiveBytes                int64       `json:"archive_bytes"`
	ExtractedBytes              int64       `json:"extracted_bytes"`
	FileCount                   int         `json:"file_count"`
	VaultFileCount              int         `json:"vault_file_count"`
	Files                       []FileProof `json:"files"`
}

type FileProof struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Response struct {
	SchemaVersion  int             `json:"schema_version"`
	Protocol       string          `json:"protocol"`
	Outcome        string          `json:"outcome"`
	RequestID      string          `json:"request_id,omitempty"`
	Retryable      bool            `json:"retryable"`
	Message        string          `json:"message,omitempty"`
	ArchiveSHA256  string          `json:"archive_sha256,omitempty"`
	Idempotent     bool            `json:"idempotent,omitempty"`
	CommitAccepted *bool           `json:"commit_accepted,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Current        json.RawMessage `json:"current,omitempty"`
}

type CurrentState struct {
	SchemaVersion           int    `json:"schema_version"`
	CurrentDeploymentID     string `json:"current_deployment_id"`
	SnapshotID              string `json:"snapshot_id"`
	RunID                   string `json:"run_id"`
	SourceFingerprint       string `json:"source_fingerprint"`
	ArtifactFingerprint     string `json:"artifact_fingerprint"`
	LogicalFingerprint      string `json:"logical_fingerprint"`
	HomeOpsVersion          string `json:"homeops_version"`
	SourceRevision          string `json:"source_revision"`
	ImageDigest             string `json:"image_digest"`
	SnapshotContractVersion string `json:"snapshot_contract_version"`
	BuildContractVersion    string `json:"build_contract_version"`
	PromotedAt              string `json:"promoted_at"`
}

type CurrentResponse struct {
	SchemaVersion int             `json:"schema_version"`
	Protocol      string          `json:"protocol"`
	Outcome       string          `json:"outcome"`
	Current       json.RawMessage `json:"current"`
}

type resultIdentity struct {
	SchemaVersion               int    `json:"schema_version"`
	Protocol                    string `json:"protocol"`
	RequestID                   string `json:"request_id"`
	PublisherID                 string `json:"publisher_id"`
	Outcome                     string `json:"outcome"`
	CandidateDeploymentID       string `json:"candidate_deployment_id"`
	ExpectedCurrentDeploymentID string `json:"expected_current_deployment_id"`
	SnapshotID                  string `json:"snapshot_id"`
	RunID                       string `json:"run_id"`
	SubmissionArchiveSHA256     string `json:"submission_archive_sha256"`
	ReleasePolicyID             string `json:"release_policy_id"`
	PromotionPolicyID           string `json:"promotion_policy_id"`
}

var allowedResultOutcomes = map[string]struct{}{
	"CANDIDATE_READY": {}, "UNCHANGED": {}, "PROMOTED": {},
	"LOCAL_VAULT_INVALID": {}, "LOCAL_SOURCE_CHANGED": {}, "PROMOTED_SOURCE_MOVED": {},
	"AUTHORIZATION_FAILED": {}, "TRANSFER_FAILED": {}, "REMOTE_SNAPSHOT_INVALID": {},
	"BUILD_FAILED": {}, "EVALUATION_FAILED": {}, "PROMOTION_CONFLICT": {},
	"POST_PROMOTION_MISMATCH": {}, "HOMEOPS_UNAVAILABLE": {}, "TIMEOUT": {}, "INTERNAL_ERROR": {},
}

var allowedResultFields = map[string]struct{}{
	"schema_version": {}, "protocol": {}, "request_id": {}, "publisher_id": {},
	"outcome": {}, "candidate_deployment_id": {}, "expected_current_deployment_id": {},
	"snapshot_id": {}, "run_id": {}, "submission_archive_sha256": {},
	"release_policy_id": {}, "promotion_policy_id": {}, "promoted_at": {}, "retryable": {},
	"diagnostic": {}, // validated but deliberately stripped before forwarding
}

type CommitAuthorization struct {
	SchemaVersion               int    `json:"schema_version"`
	Protocol                    string `json:"protocol"`
	RequestID                   string `json:"request_id"`
	PublisherID                 string `json:"publisher_id"`
	CandidateDeploymentID       string `json:"candidate_deployment_id"`
	ExpectedCurrentDeploymentID string `json:"expected_current_deployment_id"`
	SubmissionArchiveSHA256     string `json:"submission_archive_sha256"`
}

func validateCommon(schema int, protocol, requestID, publisherID, configuredPublisher string) error {
	if schema != 1 {
		return errors.New("unsupported schema version")
	}
	if protocol != Protocol {
		return errors.New("unsupported protocol")
	}
	if !uuidV4Pattern.MatchString(requestID) {
		return errors.New("request ID must be a lowercase UUIDv4")
	}
	if publisherID != configuredPublisher {
		return errors.New("publisher ownership mismatch")
	}
	return nil
}

func (r SubmissionRequest) validate(publisher string) error {
	if err := validateCommon(r.SchemaVersion, r.Protocol, r.RequestID, r.PublisherID, publisher); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(r.SnapshotID) {
		return errors.New("snapshot ID must be a lowercase SHA-256 digest")
	}
	if !sha256Pattern.MatchString(r.ReleasePolicyID) {
		return errors.New("release policy ID must be a lowercase SHA-256 digest")
	}
	if !sha256Pattern.MatchString(r.SnapshotManifestSHA256) {
		return errors.New("snapshot manifest hash must be a lowercase SHA-256 digest")
	}
	if !sha256Pattern.MatchString(r.CapabilityToken) {
		return errors.New("capability token must be 32 random bytes encoded as lowercase hexadecimal")
	}
	if err := emptyOrSHA256(r.ExpectedCurrentDeploymentID); err != nil {
		return errors.New("expected deployment ID is invalid")
	}
	return nil
}

func (r StatusRequest) validate(publisher string) error {
	if err := validateCommon(r.SchemaVersion, r.Protocol, r.RequestID, r.PublisherID, publisher); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(r.CapabilityToken) {
		return errors.New("capability token is invalid")
	}
	return nil
}

func (r CommitRequest) validate(publisher string) error {
	if err := validateCommon(r.SchemaVersion, r.Protocol, r.RequestID, r.PublisherID, publisher); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(r.CandidateDeploymentID) {
		return errors.New("candidate deployment ID is invalid")
	}
	if !sha256Pattern.MatchString(r.CapabilityToken) {
		return errors.New("capability token is invalid")
	}
	if err := emptyOrSHA256(r.ExpectedCurrentDeploymentID); err != nil {
		return errors.New("expected deployment ID is invalid")
	}
	return nil
}

func capabilityDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", digest[:])
}

func capabilityMatches(token, expectedDigest string) bool {
	actual := capabilityDigest(token)
	if len(actual) != len(expectedDigest) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedDigest)) == 1
}

func decodeCanonical[T any](data []byte, target *T) error {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return errors.New("control JSON must be one newline-terminated line")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode control JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("control JSON contains trailing data")
	}
	canonical, err := canonicalJSON(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("control JSON is not canonical")
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return append(encoded, '\n'), nil
}

func validateResultPayload(data []byte, capability string) error {
	_, err := sanitizeResultPayload(data, capability)
	return err
}

func sanitizeResultPayload(data []byte, capability string) (json.RawMessage, error) {
	if err := validateSecurePayload(data, capability, capabilityDigest(capability)); err != nil {
		return nil, err
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	for field := range result {
		if _, allowed := allowedResultFields[field]; !allowed {
			return nil, fmt.Errorf("result field is not allowed: %s", field)
		}
	}
	identityData, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	identity, err := parseResultIdentity(identityData)
	if err != nil || identity.SchemaVersion != 1 || identity.Protocol != Protocol ||
		!uuidV4Pattern.MatchString(identity.RequestID) || identity.PublisherID == "" {
		return nil, errors.New("result identity is invalid")
	}
	if _, allowed := allowedResultOutcomes[identity.Outcome]; !allowed {
		return nil, errors.New("result outcome is invalid")
	}
	if retryable, ok := result["retryable"]; !ok {
		return nil, errors.New("result retryable flag is missing")
	} else if _, ok := retryable.(bool); !ok {
		return nil, errors.New("result retryable flag is invalid")
	}
	for _, field := range []string{"candidate_deployment_id", "snapshot_id", "submission_archive_sha256", "release_policy_id", "promotion_policy_id"} {
		if value, present := result[field]; present {
			text, ok := value.(string)
			if !ok || !sha256Pattern.MatchString(text) {
				return nil, fmt.Errorf("result %s is invalid", field)
			}
		}
	}
	if value, present := result["expected_current_deployment_id"]; present {
		text, ok := value.(string)
		if !ok || emptyOrSHA256(text) != nil {
			return nil, errors.New("result expected deployment is invalid")
		}
	}
	if value, present := result["run_id"]; present {
		text, ok := value.(string)
		if !ok || !opaqueIDPattern.MatchString(text) {
			return nil, errors.New("result run ID is invalid")
		}
	}
	if value, present := result["promoted_at"]; present {
		text, ok := value.(string)
		if !ok || len(text) > 64 {
			return nil, errors.New("result promotion timestamp is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			return nil, errors.New("result promotion timestamp is invalid")
		}
	}
	if value, present := result["diagnostic"]; present {
		text, ok := value.(string)
		if !ok || len(text) > 500 {
			return nil, errors.New("result diagnostic is invalid")
		}
		delete(result, "diagnostic")
	}
	if identity.Outcome == "CANDIDATE_READY" || identity.Outcome == "PROMOTED" || identity.Outcome == "UNCHANGED" {
		for _, field := range []string{
			"candidate_deployment_id", "expected_current_deployment_id", "snapshot_id",
			"run_id", "submission_archive_sha256", "release_policy_id", "promotion_policy_id",
		} {
			if _, present := result[field]; !present {
				return nil, fmt.Errorf("candidate-ready result lacks %s", field)
			}
		}
	}
	sanitized, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(sanitized), nil
}

func validateCurrentPayload(data []byte) error {
	if err := validateSecurePayload(data); err != nil {
		return err
	}
	var state CurrentState
	if err := decodeCanonical(data, &state); err != nil {
		return err
	}
	if state.SchemaVersion != 2 {
		return errors.New("unsupported current-state schema")
	}
	if err := emptyOrSHA256(state.CurrentDeploymentID); err != nil {
		return errors.New("invalid current deployment ID")
	}
	if err := emptyOrSHA256(state.SnapshotID); err != nil {
		return errors.New("invalid snapshot ID")
	}
	if state.RunID != "" && !opaqueIDPattern.MatchString(state.RunID) {
		return errors.New("invalid run ID")
	}
	for _, fingerprint := range []string{state.SourceFingerprint, state.ArtifactFingerprint, state.LogicalFingerprint} {
		if err := emptyOrSHA256(fingerprint); err != nil {
			return errors.New("invalid current fingerprint")
		}
	}
	for _, metadata := range []string{
		state.HomeOpsVersion, state.SourceRevision, state.ImageDigest,
		state.SnapshotContractVersion, state.BuildContractVersion,
	} {
		if metadata != "" && !metadataPattern.MatchString(metadata) {
			return errors.New("invalid current build identity")
		}
	}
	if state.PromotedAt != "" {
		if len(state.PromotedAt) > 64 {
			return errors.New("invalid promotion timestamp")
		}
		if _, err := time.Parse(time.RFC3339Nano, state.PromotedAt); err != nil {
			return errors.New("invalid promotion timestamp")
		}
	}
	empty := state.CurrentDeploymentID == "" && state.SnapshotID == "" && state.RunID == "" &&
		state.SourceFingerprint == "" && state.ArtifactFingerprint == "" && state.LogicalFingerprint == "" &&
		state.HomeOpsVersion == "" && state.SourceRevision == "" && state.ImageDigest == "" &&
		state.SnapshotContractVersion == "" && state.BuildContractVersion == "" && state.PromotedAt == ""
	complete := state.CurrentDeploymentID != "" && state.SnapshotID != "" && state.RunID != "" &&
		state.SourceFingerprint != "" && state.ArtifactFingerprint != "" && state.LogicalFingerprint != "" &&
		state.HomeOpsVersion != "" && state.SourceRevision != "" && state.ImageDigest != "" &&
		state.SnapshotContractVersion != "" && state.BuildContractVersion != "" && state.PromotedAt != ""
	if !empty && !complete {
		return errors.New("current state must be entirely empty or complete")
	}
	return nil
}

func emptyOrSHA256(value string) error {
	if value == "" || sha256Pattern.MatchString(value) {
		return nil
	}
	return errors.New("not empty or SHA-256")
}

func validateSecurePayload(data []byte, prohibitedValues ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	opening, ok := token.(json.Delim)
	if !ok || opening != '{' {
		return errors.New("result must be a JSON object")
	}
	if err := validateJSONContainer(decoder, opening, prohibitedValues); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("result contains trailing data")
	}
	return nil
}

func validateJSONContainer(decoder *json.Decoder, opening json.Delim, prohibitedValues []string) error {
	if opening == '{' {
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("result object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("result contains duplicate object keys")
			}
			seen[key] = struct{}{}
			if key == "capability_token" || key == "capability_sha256" {
				return errors.New("result contains prohibited capability data")
			}
			if err := validateJSONValue(decoder, prohibitedValues); err != nil {
				return err
			}
		}
	} else {
		for decoder.More() {
			if err := validateJSONValue(decoder, prohibitedValues); err != nil {
				return err
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	expected := json.Delim(']')
	if opening == '{' {
		expected = '}'
	}
	if closing != expected {
		return errors.New("result JSON container is malformed")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, prohibitedValues []string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); ok {
		if delimiter != '{' && delimiter != '[' {
			return errors.New("unexpected closing JSON delimiter")
		}
		return validateJSONContainer(decoder, delimiter, prohibitedValues)
	}
	if value, ok := token.(string); ok {
		for _, prohibited := range prohibitedValues {
			if prohibited != "" && value == prohibited {
				return errors.New("result contains prohibited capability data")
			}
		}
	}
	return nil
}
