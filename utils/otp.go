package utils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

// buildEmailMessage assembles an RFC 5322–compliant message suitable for
// hand-off to smtp.SendMail. Historical bug: every call site in this file
// previously emitted only "To:" + "Subject:" — no From, no Date, no
// Message-ID, no MIME-Version, no Content-Type. ElasticEmail (port 2525)
// accepts such messages with a 250 OK, but Gmail/Outlook spam-filter or
// silently drop them because they violate RFC 5322 §3.6 (Date and From are
// REQUIRED). Symptom: "successfully sent" in logs, nothing in user's inbox.
//
// Sender-domain note: the From: header MUST use the same domain whose SPF/DKIM
// is configured at the relay (here: authsec.ai via ElasticEmail). Mismatch =
// DMARC fail = silent drop on Gmail.
func buildEmailMessage(toEmail, subject, body string) []byte {
	fromAddr := config.AppConfig.SMTPUser
	if fromName := strings.TrimSpace(config.AppConfig.SMTPFromName); fromName != "" {
		fromAddr = fmt.Sprintf("%s <%s>", fromName, config.AppConfig.SMTPUser)
	}
	messageID := fmt.Sprintf("<%s@authsec.ai>", uuid.NewString())
	date := time.Now().UTC().Format(time.RFC1123Z)

	var sb strings.Builder
	sb.WriteString("From: " + fromAddr + "\r\n")
	sb.WriteString("To: " + toEmail + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("Date: " + date + "\r\n")
	sb.WriteString("Message-ID: " + messageID + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}

// GenerateOTPFunc is the function variable for generating OTPs, allowing for mocking in tests
var GenerateOTPFunc = func() (string, error) {
	max := big.NewInt(999999)
	min := big.NewInt(100000)

	n, err := rand.Int(rand.Reader, max.Sub(max, min))
	if err != nil {
		return "", err
	}

	otp := n.Add(n, min).String()
	return otp, nil
}

// GenerateOTP generates a 6-digit OTP using the swappable function variable
func GenerateOTP() (string, error) {
	return GenerateOTPFunc()
}

// SendOTPEmailFunc is the function variable for sending OTP emails, allowing for mocking in tests
var SendOTPEmailFunc = func(email, otp string) error {
	log.Printf("SendOTPEmail: preparing OTP email for %s", email)
	// Email configuration from environment variables
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		// No SMTP configured — log the OTP so the operator can read it from
		// the backend logs. This keeps registration usable in dev/single-node
		// deploys without a real mail provider.
		log.Printf("SendOTPEmail: SMTP not configured — OTP for %s: %s", email, otp)
		return nil
	}

	log.Printf("SendOTPEmail: using SMTP host=%s port=%s user=%s", smtpHost, smtpPort, smtpUser)

	// Email content
	subject := "Email Verification - Your OTP Code"
	body := fmt.Sprintf(`
Dear User,

Your email verification OTP is: %s

This OTP will expire in 10 minutes. Please do not share this code with anyone.

If you didn't request this verification, please ignore this email.

Best regards,
Your App Team
    `, otp)

	// SMTP authentication
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send email
	log.Printf("SendOTPEmail: attempting to send OTP email to %s", email)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		buildEmailMessage(email, subject, body),
	)

	if err != nil {
		log.Printf("SendOTPEmail: failed to send OTP email to %s: %v", email, err)
	} else {
		log.Printf("SendOTPEmail: successfully sent OTP email to %s", email)
	}

	return err
}

// SendOTPEmail sends OTP via email using the swappable function variable
func SendOTPEmail(email, otp string) error {
	return SendOTPEmailFunc(email, otp)
}

// Add this function to your utils/otp.go file alongside your existing SendOTPEmail function

// SendPasswordResetOTPEmailFunc is the function variable for sending password reset OTP emails
var SendPasswordResetOTPEmailFunc = func(email, otp string) error {
	log.Printf("SendPasswordResetOTPEmail: preparing password reset OTP email for %s", email)
	// Email configuration from environment variables (same as existing function)
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendPasswordResetOTPEmail: SMTP not configured — OTP for %s: %s", email, otp)
		return nil
	}

	log.Printf("SendPasswordResetOTPEmail: using SMTP host=%s port=%s user=%s", smtpHost, smtpPort, smtpUser)

	// Password reset email content
	subject := "Password Reset - Your OTP Code"
	body := fmt.Sprintf(`
Dear User,

You have requested to reset your password. Your password reset OTP is: %s

This OTP will expire in 10 minutes. Please do not share this code with anyone.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Best regards,
Your App Team
    `, otp)

	// SMTP authentication (same as existing function)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send email
	log.Printf("SendPasswordResetOTPEmail: attempting to send password reset OTP email to %s", email)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		buildEmailMessage(email, subject, body),
	)

	if err != nil {
		log.Printf("SendPasswordResetOTPEmail: failed to send password reset OTP email to %s: %v", email, err)
	} else {
		log.Printf("SendPasswordResetOTPEmail: successfully sent password reset OTP email to %s", email)
	}

	return err
}

// SendPasswordResetOTPEmail sends password reset OTP via email using the swappable function variable
func SendPasswordResetOTPEmail(email, otp string) error {
	return SendPasswordResetOTPEmailFunc(email, otp)
}

func GenerateTemporaryPassword() (string, error) {
	const (
		length = 20 // Consistent with admin invite password length
		chars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	)

	password := make([]byte, length)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = chars[n.Int64()]
	}

	return string(password), nil
}

// SendTemporaryPasswordEmail sends temporary password via email
func SendTemporaryPasswordEmail(email, tempPassword string) error {
	// Email configuration from environment variables (same as existing function)
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	// Temporary password email content
	subject := "Temporary Password - Account Access"
	body := fmt.Sprintf(`
Dear User,

Your account password has been reset by an administrator. Please use the following temporary password to log in:

Temporary Password: %s

IMPORTANT:
- This is a temporary password generated by an administrator
- Please change this password immediately after logging in
- For security reasons, do not share this password with anyone

If you did not request this password reset, please contact your administrator immediately.

Best regards,
Your Security Team
    `, tempPassword)

	// SMTP authentication (same as existing function)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send email
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		buildEmailMessage(email, subject, body),
	)

	return err
}

// SendAdminInviteEmail sends a tailored invite email for admin users with login URL, username, and temp password.
func SendAdminInviteEmail(email, username, workspaceDomain, tempPassword string) error {
	log.Printf("SendAdminInviteEmail: preparing admin invite email for %s", email)
	// Email configuration from environment variables
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendAdminInviteEmail: incomplete SMTP configuration (host=%q port=%q user=%q)", smtpHost, smtpPort, smtpUser)
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	// Build login URL from tenant domain; fall back to base URL if tenant domain missing.
	loginURL := strings.TrimSpace(workspaceDomain)
	if loginURL == "" {
		loginURL = strings.TrimSpace(config.AppConfig.BaseURL)
	}
	if loginURL != "" && !strings.HasPrefix(strings.ToLower(loginURL), "http") {
		loginURL = "https://" + loginURL
	}

	log.Printf("SendAdminInviteEmail: using SMTP host=%s port=%s user=%s", smtpHost, smtpPort, smtpUser)

	subject := "You have been invited to AuthSec"
	body := fmt.Sprintf(`
Hello,

You have been invited to AuthSec. Use the details below to sign in:

- Username: %s
- Temporary Password: %s
- Login URL: %s

This temporary password is valid for your first login. Please sign in and change it immediately.

If you did not expect this invite, contact your administrator.

Regards,
AuthSec Team
`, username, tempPassword, loginURL)

	// SMTP authentication
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send email
	log.Printf("SendAdminInviteEmail: attempting to send admin invite email to %s", email)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		buildEmailMessage(email, subject, body),
	)

	if err != nil {
		log.Printf("SendAdminInviteEmail: failed to send admin invite email to %s: %v", email, err)
	} else {
		log.Printf("SendAdminInviteEmail: successfully sent admin invite email to %s", email)
	}

	return err
}

// SendAccountDeactivationEmail sends notification when user account is deactivated
func SendAccountDeactivationEmail(email string) error {
	log.Printf("SendAccountDeactivationEmail: preparing deactivation email for %s", email)
	// Email configuration from environment variables
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendAccountDeactivationEmail: incomplete SMTP configuration (host=%q port=%q user=%q)", smtpHost, smtpPort, smtpUser)
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	log.Printf("SendAccountDeactivationEmail: using SMTP host=%s port=%s user=%s", smtpHost, smtpPort, smtpUser)

	// Account deactivation email content
	subject := "Account Deactivation Notice"
	body := `
Dear User,

Your account has been deactivated by an administrator.

You will no longer be able to access the system with this account. If you believe this was done in error or if you need to regain access, please contact your system administrator.

If you have any questions or concerns, please reach out to our support team.

Best regards,
Your Security Team
    `

	// SMTP authentication
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send email
	log.Printf("SendAccountDeactivationEmail: attempting to send deactivation email to %s", email)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		buildEmailMessage(email, subject, body),
	)

	if err != nil {
		log.Printf("SendAccountDeactivationEmail: failed to send deactivation email to %s: %v", email, err)
	} else {
		log.Printf("SendAccountDeactivationEmail: successfully sent deactivation email to %s", email)
	}

	return err
}

// SendNewUserRegistrationNotificationEmail sends a notification to the tenant owner when a new user registers.
// SendAccessRequestNotificationEmail notifies a workspace admin that a new
// cross-workspace access request is pending their approval or that an existing
// pending request is about to expire (indicated by expiryWarning=true).
func SendAccessRequestNotificationEmail(adminEmail, requestID, clientID, rsName, requestedScopes, statusURL string, expiresAt time.Time, expiryWarning bool) error {
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword
	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendAccessRequestNotificationEmail: SMTP not configured")
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	var subject, body string
	if expiryWarning {
		subject = "Action required: cross-workspace access request expiring soon"
		body = fmt.Sprintf(`Hello,

A pending cross-workspace access request for "%s" will expire at %s unless approved.

- Request ID:      %s
- Requesting client: %s
- Requested scopes:  %s
- Expires at:        %s

Review and approve or deny at:
%s

Regards,
AuthSec Team
`, rsName, expiresAt.UTC().Format(time.RFC1123),
			requestID, clientID, requestedScopes,
			expiresAt.UTC().Format(time.RFC1123), statusURL)
	} else {
		subject = "New cross-workspace access request pending approval"
		body = fmt.Sprintf(`Hello,

A new cross-workspace access request requires your approval.

- Request ID:        %s
- Requesting client: %s
- Target resource:   %s
- Requested scopes:  %s
- Expires at:        %s

Review and approve or deny at:
%s

Regards,
AuthSec Team
`, requestID, clientID, rsName, requestedScopes,
			expiresAt.UTC().Format(time.RFC1123), statusURL)
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{adminEmail},
		buildEmailMessage(adminEmail, subject, body),
	)
	if err != nil {
		log.Printf("SendAccessRequestNotificationEmail: failed to notify %s: %v", adminEmail, err)
	} else {
		log.Printf("SendAccessRequestNotificationEmail: notified %s (req=%s expiry_warning=%v)", adminEmail, requestID, expiryWarning)
	}
	return err
}

func SendNewUserRegistrationNotificationEmail(ownerEmail, userName, userEmail, workspaceDomain string) error {
	log.Printf("SendNewUserRegistrationNotificationEmail: preparing notification email for owner %s", ownerEmail)

	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendNewUserRegistrationNotificationEmail: incomplete SMTP configuration (host=%q port=%q user=%q)", smtpHost, smtpPort, smtpUser)
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	log.Printf("SendNewUserRegistrationNotificationEmail: using SMTP host=%s port=%s user=%s", smtpHost, smtpPort, smtpUser)

	subject := "New User Registration Notification"
	body := fmt.Sprintf(`
Hello,

A new user has registered under your tenant.

- Name: %s
- Email: %s
- Tenant Domain: %s
- Registration Time: %s

If you did not expect this registration, please review your tenant settings.

Regards,
AuthSec Team
`, userName, userEmail, workspaceDomain, time.Now().UTC().Format(time.RFC1123))

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	log.Printf("SendNewUserRegistrationNotificationEmail: attempting to send notification email to %s", ownerEmail)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{ownerEmail},
		buildEmailMessage(ownerEmail, subject, body),
	)

	if err != nil {
		log.Printf("SendNewUserRegistrationNotificationEmail: failed to send notification email to %s: %v", ownerEmail, err)
	} else {
		log.Printf("SendNewUserRegistrationNotificationEmail: successfully sent notification email to %s", ownerEmail)
	}

	return err
}
