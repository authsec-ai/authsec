package lockout

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ErrLocked is returned by the guards while an account is locked. Map it to
// 429 with Retry-After.
var ErrLocked = errors.New(Message)

// MatchTOTPStep returns the 30-second time step whose code equals code,
// trying the current step and window steps either side. ok is false when no
// step matches.
func MatchTOTPStep(secret, code string, window int) (step int64, ok bool) {
	now := time.Now()
	for i := -window; i <= window; i++ {
		t := now.Add(time.Duration(i) * 30 * time.Second)
		valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
			Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && valid {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}

// consumeTOTPStep records that a step was accepted for a user. It returns
// false when the step had already been accepted (a replay).
func consumeTOTPStep(ctx context.Context, db *sql.DB, ws, userID uuid.UUID, step int64) (bool, error) {
	sctx := scoped(ctx, ws)
	_, _ = tenancy.ExecContext(sctx, db,
		`DELETE FROM totp_used_steps WHERE workspace_id = $1 AND user_id = $2 AND used_at < now() - interval '10 minutes'`, userID)
	res, err := tenancy.ExecContext(sctx, db, `
		INSERT INTO totp_used_steps (workspace_id, user_id, step)
		SELECT $1, $2, $3 WHERE NOT EXISTS (
		  SELECT 1 FROM totp_used_steps WHERE workspace_id = $1 AND user_id = $2 AND step = $3)
		ON CONFLICT DO NOTHING`, userID, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// GuardCode runs one second-factor verification for a user under the lockout
// and replay rules:
//
//   - while the account is locked for kind, it returns ErrLocked without
//     calling match;
//   - match reports whether the code is valid and, for TOTP, the matched time
//     step (step < 0 means the factor has no steps, e.g. an SMS code);
//   - a TOTP step is accepted once per user: a second use is a failure;
//   - a failure is counted; a success clears the counter.
//
// Without a database (unit tests) it only calls match.
func GuardCode(ctx context.Context, db *sql.DB, ws, userID uuid.UUID, kind Kind, match func() (step int64, ok bool)) (bool, error) {
	if db == nil || ws == uuid.Nil || userID == uuid.Nil {
		_, ok := match()
		return ok, nil
	}
	subject := userID.String()
	if locked, _, err := Locked(ctx, db, ws, kind, subject); locked {
		if err != nil {
			return false, err
		}
		return false, ErrLocked
	}
	step, ok := match()
	if ok && step >= 0 {
		fresh, err := consumeTOTPStep(ctx, db, ws, userID, step)
		if err != nil {
			return false, err
		}
		ok = fresh
	}
	if ok {
		_ = Succeed(ctx, db, ws, kind, subject)
		return true, nil
	}
	if locked, _, err := Fail(ctx, db, ws, kind, subject); err == nil && locked {
		return false, ErrLocked
	}
	return false, nil
}
