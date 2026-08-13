package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/tenenwurcel/homeops-ai/internal/receiver"
)

func main() {
	config := receiver.Config{}
	flag.StringVar(&config.IncomingDir, "incoming-dir", os.Getenv("HOMEOPS_RECEIVER_INCOMING_DIR"), "trusted incoming root")
	flag.StringVar(&config.ResultsDir, "results-dir", os.Getenv("HOMEOPS_RECEIVER_RESULTS_DIR"), "trusted result root")
	flag.StringVar(&config.CommitsDir, "commits-dir", os.Getenv("HOMEOPS_RECEIVER_COMMITS_DIR"), "trusted commit root")
	flag.StringVar(&config.PublisherID, "publisher-id", os.Getenv("HOMEOPS_RECEIVER_PUBLISHER_ID"), "publisher identity bound to this forced command")
	flag.StringVar(&config.ConsumerGroup, "consumer-group", os.Getenv("HOMEOPS_RECEIVER_CONSUMER_GROUP"), "trusted processor group granted read-only access")
	flag.StringVar(&config.ConsumerUser, "consumer-user", os.Getenv("HOMEOPS_RECEIVER_CONSUMER_USER"), "trusted processor user")
	flag.StringVar(&config.CurrentStateFile, "current-state-file", os.Getenv("HOMEOPS_RECEIVER_CURRENT_STATE_FILE"), "trusted redacted current-deployment state")
	flag.Int64Var(&config.MaxArchiveBytes, "max-archive-bytes", envInt64("HOMEOPS_RECEIVER_MAX_ARCHIVE_BYTES"), "maximum raw USTAR bytes")
	flag.Int64Var(&config.MaxExtractedBytes, "max-extracted-bytes", envInt64("HOMEOPS_RECEIVER_MAX_EXTRACTED_BYTES"), "maximum extracted payload bytes")
	flag.Int64Var(&config.MaxFileBytes, "max-file-bytes", envInt64("HOMEOPS_RECEIVER_MAX_FILE_BYTES"), "maximum individual payload bytes")
	flag.IntVar(&config.MaxFiles, "max-files", envInt("HOMEOPS_RECEIVER_MAX_FILES"), "maximum regular files")
	flag.Int64Var(&config.MaxControlBytes, "max-control-bytes", envInt64("HOMEOPS_RECEIVER_MAX_CONTROL_BYTES"), "maximum status or commit frame bytes")
	flag.Int64Var(&config.MaxResultBytes, "max-result-bytes", envInt64("HOMEOPS_RECEIVER_MAX_RESULT_BYTES"), "maximum builder result bytes")
	flag.Parse()
	if flag.NArg() != 0 {
		writeStartupFailure()
	}
	config.RequireRoot = true
	if config.ConsumerGroup == "" || config.ConsumerUser == "" {
		writeStartupFailure()
	}

	server, err := receiver.New(config)
	if err != nil {
		writeStartupFailure()
	}
	exitCode := server.Run(
		os.Getenv("SSH_ORIGINAL_COMMAND"),
		os.Getenv("SSH_TTY"),
		os.Stdin,
		os.Stdout,
		os.Stderr,
	)
	os.Exit(exitCode)
}

func envInt64(name string) int64 {
	value := os.Getenv(name)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		writeStartupFailure()
	}
	return parsed
}

func envInt(name string) int {
	value := envInt64(name)
	if value > int64(^uint(0)>>1) {
		writeStartupFailure()
	}
	return int(value)
}

func writeStartupFailure() {
	_, _ = fmt.Fprintln(os.Stdout, `{"schema_version":1,"protocol":"homeops.receiver/v1","outcome":"INTERNAL_ERROR","retryable":false,"message":"receiver configuration is invalid"}`)
	os.Exit(78)
}
