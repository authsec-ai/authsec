package awsdiscovery

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// The account-wide credential report: one row per IAM user, covering password
// and access-key age and last use in a single call instead of two calls
// (ListAccessKeys, GetAccessKeyLastUsed) per user plus no way at all to read
// password state or MFA enrollment.
//
// WHY THIS EXISTS ALONGSIDE ListAccessKeys/GetAccessKeyLastUsed, NOT INSTEAD
// OF THEM. The report adds three things per-key reads cannot see at all:
// whether a console password exists and when it was last used, whether MFA is
// active, and a key's rotation date (as opposed to its last-used date -- an
// old, frequently-used key and a young, never-used one look identical to the
// per-key calls, and are opposite findings). It is recorded as evidence
// alongside the existing identity rows, not as a replacement inventory path.
//
// WHY THE POLL LOOP LOOKS LIKE ACTIVITY'S. GenerateCredentialReport starts a
// job; a report is not ready to fetch until AWS finishes building it, and
// GetCredentialReport returns ReportInProgressException until then. Same
// structural shape as ServiceLastAccessedAPI, same reason to bound both the
// interval and the total wait.

// CredentialReportAPI is the slice of IAM used for the credential report.
type CredentialReportAPI interface {
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

// NewCredentialReportClient builds a real IAM client for the credential
// report. IAM is global, so this is not region-bound.
func NewCredentialReportClient(cfg aws.Config) CredentialReportAPI {
	return iam.NewFromConfig(cfg)
}

// ErrCredentialReportTimeout means the report did not become ready inside the
// budget. Distinct from a denied read: AWS accepted the request and is still
// working on it.
var ErrCredentialReportTimeout = errors.New("the credential report did not become ready in time")

const (
	credentialReportPollInterval = 2 * time.Second
	credentialReportPollTimeout  = 30 * time.Second
)

// CredentialReportRow is one IAM user's row from the account credential
// report. Booleans and dates are exactly what AWS reported; "N/A" and "not
// supported" both decode to a nil pointer or false, since neither is a date
// or an active credential.
type CredentialReportRow struct {
	UserARN               string
	PasswordEnabled       bool
	PasswordLastUsed      *time.Time
	MFAActive             bool
	AccessKey1Active      bool
	AccessKey1LastRotated *time.Time
	AccessKey1LastUsedAt  *time.Time
	AccessKey2Active      bool
	AccessKey2LastRotated *time.Time
	AccessKey2LastUsedAt  *time.Time
}

// CredentialReportReader reads the account's IAM credential report.
type CredentialReportReader struct {
	api   CredentialReportAPI
	sleep func(context.Context, time.Duration) error
}

// NewCredentialReportReader constructs a reader over the given API.
func NewCredentialReportReader(api CredentialReportAPI) *CredentialReportReader {
	return &CredentialReportReader{api: api, sleep: sleepCtx}
}

// WithSleep replaces the inter-poll delay, so a test does not wait for real.
func (r *CredentialReportReader) WithSleep(f func(context.Context, time.Duration) error) *CredentialReportReader {
	r.sleep = f
	return r
}

// Report generates and fetches the current account credential report,
// parsed into one row per IAM user.
//
// GenerateCredentialReport is idempotent to call repeatedly -- AWS caches the
// report for up to four hours -- so this always calls it first rather than
// trying GetCredentialReport optimistically and generating only on failure:
// that would mean two round trips in the common case instead of one.
func (r *CredentialReportReader) Report(ctx context.Context) ([]CredentialReportRow, error) {
	if r.api == nil {
		return nil, nil
	}

	if _, err := r.api.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, classify(err)
	}

	deadline := time.Now().Add(credentialReportPollTimeout)
	for {
		out, err := r.api.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			return parseCredentialReport(out.Content)
		}
		if !isReportInProgress(err) {
			return nil, classify(err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: after %s", ErrCredentialReportTimeout, credentialReportPollTimeout)
		}
		if err := r.sleep(ctx, credentialReportPollInterval); err != nil {
			return nil, err
		}
	}
}

// isReportInProgress reports whether AWS refused the read because the report
// it just started is not built yet, as opposed to a real denial.
func isReportInProgress(err error) bool {
	var reportErr *iamtypes.CredentialReportNotReadyException
	if errors.As(err, &reportErr) {
		return true
	}
	// The generated exception type is only reliably matched via errors.As when
	// the SDK deserialised it as that concrete type; smithy's generic API
	// error carries the same code as a fallback for transports that do not.
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ReportInProgress"
	}
	return false
}

// credentialReportColumns are the header names this parser reads, out of the
// ~20 AWS defines. Matched by name rather than position: AWS documents the
// order but a parser keyed on it breaks the moment that changes upstream, and
// costs nothing to avoid.
const (
	colUser                  = "user"
	colARN                   = "arn"
	colPasswordEnabled       = "password_enabled"
	colPasswordLastUsed      = "password_last_used"
	colMFAActive             = "mfa_active"
	colAccessKey1Active      = "access_key_1_active"
	colAccessKey1LastRotated = "access_key_1_last_rotated"
	colAccessKey1LastUsed    = "access_key_1_last_used_date"
	colAccessKey2Active      = "access_key_2_active"
	colAccessKey2LastRotated = "access_key_2_last_rotated"
	colAccessKey2LastUsed    = "access_key_2_last_used_date"
)

// parseCredentialReport reads the CSV AWS returned into one row per real IAM
// user, skipping the synthetic <root_account> row: it is not an
// identity this discovery tracks, and its access-key columns are always
// "not_supported" in a way that would otherwise parse as false-but-present.
func parseCredentialReport(content []byte) ([]CredentialReportRow, error) {
	cr := csv.NewReader(bytes.NewReader(content))
	header, err := cr.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("credential report has no header: %w", err)
	}
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[name] = i
	}

	get := func(row []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}

	var out []CredentialReportRow
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("credential report row: %w", err)
		}
		if get(row, colUser) == "<root_account>" {
			continue
		}
		out = append(out, CredentialReportRow{
			UserARN:               get(row, colARN),
			PasswordEnabled:       get(row, colPasswordEnabled) == "true",
			PasswordLastUsed:      parseReportTime(get(row, colPasswordLastUsed)),
			MFAActive:             get(row, colMFAActive) == "true",
			AccessKey1Active:      get(row, colAccessKey1Active) == "true",
			AccessKey1LastRotated: parseReportTime(get(row, colAccessKey1LastRotated)),
			AccessKey1LastUsedAt:  parseReportTime(get(row, colAccessKey1LastUsed)),
			AccessKey2Active:      get(row, colAccessKey2Active) == "true",
			AccessKey2LastRotated: parseReportTime(get(row, colAccessKey2LastRotated)),
			AccessKey2LastUsedAt:  parseReportTime(get(row, colAccessKey2LastUsed)),
		})
	}
	return out, nil
}

// parseReportTime decodes one credential-report date cell. AWS uses "N/A" for
// a password/key that was never used and "not_supported" for a cell that does
// not apply to this row's kind of credential; both mean "no date", the same
// as a genuinely empty cell, and none of the three is a parse error.
func parseReportTime(s string) *time.Time {
	if s == "" || s == "N/A" || s == "not_supported" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
