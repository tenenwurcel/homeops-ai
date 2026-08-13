package receiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Server struct {
	config            Config
	incomingNamespace string
	resultsNamespace  string
	commitsNamespace  string
	consumerGID       int
	consumerUID       int
}

func New(config Config) (*Server, error) {
	validated, err := config.validate()
	if err != nil {
		return nil, err
	}
	uid, gid, err := consumerIDs(validated.ConsumerUser, validated.ConsumerGroup)
	if err != nil {
		return nil, err
	}
	if validated.RequireRoot {
		if err := validateProductionOwnership(validated, uid, gid); err != nil {
			return nil, err
		}
	}
	incoming, err := ensurePublisherDir(validated.IncomingDir, validated.PublisherID)
	if err != nil {
		return nil, fmt.Errorf("invalid incoming namespace: %w", err)
	}
	results, err := ensurePublisherDir(validated.ResultsDir, validated.PublisherID)
	if err != nil {
		return nil, fmt.Errorf("invalid results namespace: %w", err)
	}
	resultsInfo, err := os.Lstat(results)
	if err != nil || resultsInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("results namespace may be writable only by its owner")
	}
	commits, err := ensurePublisherDir(validated.CommitsDir, validated.PublisherID)
	if err != nil {
		return nil, fmt.Errorf("invalid commits namespace: %w", err)
	}
	return &Server{
		config:            validated,
		incomingNamespace: incoming,
		resultsNamespace:  results,
		commitsNamespace:  commits,
		consumerGID:       gid,
		consumerUID:       uid,
	}, nil
}

// Run serves exactly one forced-command request. The caller must pass the
// unmodified SSH_ORIGINAL_COMMAND and SSH_TTY values. It returns a process exit
// code and always attempts to write one framed JSON response to stdout.
func (s *Server) Run(originalCommand, sshTTY string, input io.Reader, output, diagnostic io.Writer) int {
	if sshTTY != "" {
		return s.writeResponse(output, Response{
			Outcome: "PROTOCOL_REJECTED", Message: "PTY allocation is prohibited",
		}, 64)
	}
	switch originalCommand {
	case CommandSubmit:
		return s.handleSubmit(input, output)
	case CommandStatus:
		return s.handleStatus(input, output)
	case CommandCommit:
		return s.handleCommit(input, output)
	case CommandCurrent:
		return s.handleCurrent(input, output)
	default:
		return s.writeResponse(output, Response{
			Outcome: "PROTOCOL_REJECTED", Message: "unknown forced-command operation",
		}, 64)
	}
}

func (s *Server) handleCurrent(input io.Reader, output io.Writer) int {
	if err := rejectNonEmptyInput(input); err != nil {
		return s.invalidControl(output)
	}
	current, err := readBoundedRegular(s.config.CurrentStateFile, s.config.MaxResultBytes)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", Retryable: true, Message: "current deployment state is unavailable",
		}, 70)
	}
	if err != nil || validateCurrentPayload(current) != nil {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", Retryable: true, Message: "current deployment state is unavailable",
		}, 70)
	}
	data, encodeErr := canonicalJSON(CurrentResponse{
		SchemaVersion: 1, Protocol: Protocol, Outcome: "CURRENT", Current: json.RawMessage(current),
	})
	if encodeErr != nil {
		return 70
	}
	if _, writeErr := output.Write(data); writeErr != nil {
		return 74
	}
	return 0
}

func rejectNonEmptyInput(input io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(input, 1))
	if err != nil || len(data) != 0 {
		return errors.New("operation requires empty stdin")
	}
	return nil
}

func (s *Server) handleSubmit(input io.Reader, output io.Writer) int {
	result, err := s.receiveArchive(input)
	if err == nil {
		return s.writeResponse(output, Response{
			Outcome:       "ACCEPTED",
			RequestID:     result.receipt.RequestID,
			ArchiveSHA256: result.receipt.ArchiveSHA256,
			Idempotent:    result.idempotent,
		}, 0)
	}
	switch {
	case errors.Is(err, errRequestConflict):
		return s.writeResponse(output, Response{
			Outcome: "REQUEST_ID_CONFLICT", Message: "request ID already identifies different archive bytes",
		}, 65)
	case errors.Is(err, errArchiveLimit):
		return s.writeResponse(output, Response{
			Outcome: "ARCHIVE_LIMIT_EXCEEDED", Message: "submission exceeds a receiver limit",
		}, 65)
	case errors.Is(err, errArchiveInvalid):
		return s.writeResponse(output, Response{
			Outcome: "ARCHIVE_INVALID", Message: "submission archive is invalid",
		}, 65)
	default:
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", Retryable: true, Message: "receiver could not durably queue the submission",
		}, 70)
	}
}

func (s *Server) handleStatus(input io.Reader, output io.Writer) int {
	var request StatusRequest
	if err := s.readControl(input, &request); err != nil {
		return s.invalidControl(output)
	}
	if err := request.validate(s.config.PublisherID); err != nil {
		return s.invalidControl(output)
	}
	receipt, found := s.authorizedReceipt(request.RequestID, request.CapabilityToken)
	if !found {
		return s.writeResponse(output, Response{
			Outcome: "NOT_FOUND", RequestID: request.RequestID, Message: "request is not available to this capability",
		}, 66)
	}
	commitAccepted, commitErr := s.commitAccepted(request.RequestID, receipt)
	if commitErr != nil {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", RequestID: request.RequestID,
			Message: "commit authorization is invalid",
		}, 70)
	}
	resultPath := filepath.Join(s.resultsNamespace, request.RequestID+".json")
	result, err := readBoundedRegular(resultPath, s.config.MaxResultBytes)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeResponse(output, Response{
			Outcome: "PENDING", RequestID: request.RequestID, Retryable: true,
			ArchiveSHA256: receipt.ArchiveSHA256, CommitAccepted: boolPointer(commitAccepted),
		}, 0)
	}
	if err != nil {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", RequestID: request.RequestID, Retryable: true,
			Message: "result is temporarily unavailable",
		}, 70)
	}
	sanitized, err := sanitizeResultPayload(result, request.CapabilityToken)
	if err != nil {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", RequestID: request.RequestID,
			Message: "result payload is invalid",
		}, 70)
	}
	identity, err := parseResultIdentity(sanitized)
	if err != nil || validateResultIdentity(identity, request.RequestID, s.config.PublisherID) != nil ||
		validateResultReceipt(identity, receipt) != nil {
		return s.writeResponse(output, Response{
			Outcome: "INTERNAL_ERROR", RequestID: request.RequestID,
			Message: "result identity is invalid",
		}, 70)
	}
	return s.writeResponse(output, Response{
		Outcome: "RESULT", RequestID: request.RequestID, Result: sanitized,
		CommitAccepted: boolPointer(commitAccepted),
	}, 0)
}

func boolPointer(value bool) *bool {
	return &value
}

func (s *Server) commitAccepted(requestID string, receipt Receipt) (bool, error) {
	data, err := readBoundedRegular(filepath.Join(s.commitsNamespace, requestID+".json"), s.config.MaxControlBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var authorization CommitAuthorization
	if err := decodeCanonical(data, &authorization); err != nil {
		return false, err
	}
	if authorization.SchemaVersion != 1 || authorization.Protocol != Protocol ||
		authorization.RequestID != requestID || authorization.PublisherID != s.config.PublisherID ||
		authorization.ExpectedCurrentDeploymentID != receipt.ExpectedCurrentDeploymentID ||
		authorization.SubmissionArchiveSHA256 != receipt.ArchiveSHA256 ||
		!sha256Pattern.MatchString(authorization.CandidateDeploymentID) {
		return false, errors.New("commit authorization identity mismatch")
	}
	return true, nil
}

func (s *Server) handleCommit(input io.Reader, output io.Writer) int {
	var request CommitRequest
	if err := s.readControl(input, &request); err != nil {
		return s.invalidControl(output)
	}
	if err := request.validate(s.config.PublisherID); err != nil {
		return s.invalidControl(output)
	}
	receipt, found := s.authorizedReceipt(request.RequestID, request.CapabilityToken)
	if !found {
		return s.writeResponse(output, Response{
			Outcome: "NOT_FOUND", RequestID: request.RequestID, Message: "request is not available to this capability",
		}, 66)
	}
	if receipt.ExpectedCurrentDeploymentID != request.ExpectedCurrentDeploymentID {
		return s.writeResponse(output, Response{
			Outcome: "COMMIT_MISMATCH", RequestID: request.RequestID,
			Message: "commit does not match the submitted expected deployment",
		}, 65)
	}
	authorization := CommitAuthorization{
		SchemaVersion:               1,
		Protocol:                    Protocol,
		RequestID:                   request.RequestID,
		PublisherID:                 request.PublisherID,
		CandidateDeploymentID:       request.CandidateDeploymentID,
		ExpectedCurrentDeploymentID: request.ExpectedCurrentDeploymentID,
		SubmissionArchiveSHA256:     receipt.ArchiveSHA256,
	}
	authorizationData, err := canonicalJSON(authorization)
	if err != nil {
		return s.internalCommitError(output, request.RequestID)
	}
	commitPath := filepath.Join(s.commitsNamespace, request.RequestID+".json")
	if existing, err := readBoundedRegular(commitPath, s.config.MaxControlBytes); err == nil {
		if string(existing) == string(authorizationData) {
			return s.writeResponse(output, Response{
				Outcome: "COMMIT_ACCEPTED", RequestID: request.RequestID, Idempotent: true,
			}, 0)
		}
		return s.writeResponse(output, Response{
			Outcome: "COMMIT_CONFLICT", RequestID: request.RequestID,
			Message: "request already has different commit authorization",
		}, 65)
	} else if !errors.Is(err, os.ErrNotExist) {
		return s.internalCommitError(output, request.RequestID)
	}

	result, err := readBoundedRegular(filepath.Join(s.resultsNamespace, request.RequestID+".json"), s.config.MaxResultBytes)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeResponse(output, Response{
			Outcome: "COMMIT_NOT_READY", RequestID: request.RequestID, Retryable: true,
			Message: "candidate result is not ready",
		}, 69)
	}
	if err != nil {
		return s.internalCommitError(output, request.RequestID)
	}
	if err := validateResultPayload(result, request.CapabilityToken); err != nil {
		return s.internalCommitError(output, request.RequestID)
	}
	identity, err := parseResultIdentity(result)
	if err != nil || validateResultIdentity(identity, request.RequestID, s.config.PublisherID) != nil ||
		validateResultReceipt(identity, receipt) != nil {
		return s.internalCommitError(output, request.RequestID)
	}
	if identity.Outcome != "CANDIDATE_READY" || identity.CandidateDeploymentID != request.CandidateDeploymentID ||
		identity.ExpectedCurrentDeploymentID != request.ExpectedCurrentDeploymentID {
		return s.writeResponse(output, Response{
			Outcome: "COMMIT_MISMATCH", RequestID: request.RequestID,
			Message: "commit does not exactly match a candidate-ready result",
		}, 65)
	}
	if err := publishExclusiveOwned(s.config.CommitsDir, s.commitsNamespace, request.RequestID+".json", authorizationData, 0o640, s.consumerGID); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readBoundedRegular(commitPath, s.config.MaxControlBytes)
			if readErr == nil && string(existing) == string(authorizationData) {
				return s.writeResponse(output, Response{
					Outcome: "COMMIT_ACCEPTED", RequestID: request.RequestID, Idempotent: true,
				}, 0)
			}
			return s.writeResponse(output, Response{
				Outcome: "COMMIT_CONFLICT", RequestID: request.RequestID,
				Message: "request already has different commit authorization",
			}, 65)
		}
		return s.internalCommitError(output, request.RequestID)
	}
	return s.writeResponse(output, Response{
		Outcome: "COMMIT_ACCEPTED", RequestID: request.RequestID,
	}, 0)
}

func (s *Server) authorizedReceipt(requestID, capability string) (Receipt, bool) {
	requestDir := filepath.Join(s.incomingNamespace, requestID)
	info, err := os.Lstat(requestDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Receipt{}, false
	}
	receipt, _, err := readReceipt(filepath.Join(requestDir, "receipt.json"), s.config.MaxResultBytes)
	if err != nil || receipt.SchemaVersion != 1 || receipt.Protocol != Protocol ||
		receipt.RequestID != requestID || receipt.PublisherID != s.config.PublisherID ||
		!sha256Pattern.MatchString(receipt.CapabilitySHA256) || !capabilityMatches(capability, receipt.CapabilitySHA256) {
		return Receipt{}, false
	}
	return receipt, true
}

func validateResultIdentity(identity resultIdentity, requestID, publisherID string) error {
	if err := validateCommon(identity.SchemaVersion, identity.Protocol, identity.RequestID, identity.PublisherID, publisherID); err != nil {
		return err
	}
	if identity.RequestID != requestID || identity.Outcome == "" {
		return errors.New("result does not match request")
	}
	return nil
}

func validateResultReceipt(identity resultIdentity, receipt Receipt) error {
	if identity.SubmissionArchiveSHA256 != "" && identity.SubmissionArchiveSHA256 != receipt.ArchiveSHA256 {
		return errors.New("result archive does not match submission")
	}
	if identity.SnapshotID != "" && identity.SnapshotID != receipt.SnapshotID {
		return errors.New("result snapshot does not match submission")
	}
	if identity.ReleasePolicyID != "" && identity.ReleasePolicyID != receipt.ReleasePolicyID {
		return errors.New("result release policy does not match submission")
	}
	if identity.CandidateDeploymentID != "" && identity.ExpectedCurrentDeploymentID != receipt.ExpectedCurrentDeploymentID {
		return errors.New("result expected deployment does not match submission")
	}
	return nil
}

func (s *Server) readControl(input io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(input, s.config.MaxControlBytes+1))
	if err != nil || int64(len(data)) > s.config.MaxControlBytes {
		return errors.New("invalid control frame")
	}
	switch typed := target.(type) {
	case *StatusRequest:
		return decodeCanonical(data, typed)
	case *CommitRequest:
		return decodeCanonical(data, typed)
	default:
		return errors.New("unsupported control frame")
	}
}

func (s *Server) invalidControl(output io.Writer) int {
	return s.writeResponse(output, Response{
		Outcome: "INVALID_REQUEST", Message: "control request is invalid",
	}, 65)
}

func (s *Server) internalCommitError(output io.Writer, requestID string) int {
	return s.writeResponse(output, Response{
		Outcome: "INTERNAL_ERROR", RequestID: requestID, Retryable: true,
		Message: "receiver could not durably authorize commit",
	}, 70)
}

func (s *Server) writeResponse(output io.Writer, response Response, code int) int {
	response.SchemaVersion = 1
	response.Protocol = Protocol
	data, err := canonicalJSON(response)
	if err != nil {
		return 70
	}
	if _, err := output.Write(data); err != nil {
		return 74
	}
	return code
}
