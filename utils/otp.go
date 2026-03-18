package utils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
)

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

func emailDeliveryMode() string {
	mode := ""
	if config.AppConfig != nil {
		mode = config.AppConfig.EmailDeliveryMode
	}
	if strings.TrimSpace(mode) == "" {
		mode = os.Getenv("EMAIL_DELIVERY_MODE")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "smtp"
	}
	return mode
}

func smtpConfig() (string, string, string, string) {
	if config.AppConfig != nil {
		return config.AppConfig.SMTPHost, config.AppConfig.SMTPPort, config.AppConfig.SMTPUser, config.AppConfig.SMTPPassword
	}
	return os.Getenv("SMTP_HOST"), os.Getenv("SMTP_PORT"), os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASSWORD")
}

func sendEmail(kind, email, subject, body string) error {
	switch emailDeliveryMode() {
	case "log":
		log.Printf("[%s][LOCAL EMAIL] to=%s subject=%q\n%s", kind, email, subject, body)
		return nil
	case "smtp":
		// Use SMTP delivery below.
	default:
		log.Printf("%s: unknown EMAIL_DELIVERY_MODE %q, falling back to smtp", kind, emailDeliveryMode())
	}

	smtpHost, smtpPort, smtpUser, smtpPass := smtpConfig()
	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("%s: incomplete SMTP configuration (host=%q port=%q user=%q)", kind, smtpHost, smtpPort, smtpUser)
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	log.Printf("%s: using SMTP host=%s port=%s user=%s", kind, smtpHost, smtpPort, smtpUser)

	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email, subject, body)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	log.Printf("%s: attempting to send email to %s", kind, email)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth,
		smtpUser,
		[]string{email},
		[]byte(message),
	)
	if err != nil {
		log.Printf("%s: failed to send email to %s: %v", kind, email, err)
	} else {
		log.Printf("%s: successfully sent email to %s", kind, email)
	}
	return err
}

// SendOTPEmailFunc is the function variable for sending OTP emails, allowing for mocking in tests
var SendOTPEmailFunc = func(email, otp string) error {
	subject := "Email Verification - Your OTP Code"
	body := fmt.Sprintf(`
Dear User,

Your email verification OTP is: %s

This OTP will expire in 10 minutes. Please do not share this code with anyone.

If you didn't request this verification, please ignore this email.

Best regards,
Your App Team
    `, otp)
	return sendEmail("SendOTPEmail", email, subject, body)
}

// SendOTPEmail sends OTP via email using the swappable function variable
func SendOTPEmail(email, otp string) error {
	return SendOTPEmailFunc(email, otp)
}

// Add this function to your utils/otp.go file alongside your existing SendOTPEmail function

// SendPasswordResetOTPEmailFunc is the function variable for sending password reset OTP emails
var SendPasswordResetOTPEmailFunc = func(email, otp string) error {
	subject := "Password Reset - Your OTP Code"
	body := fmt.Sprintf(`
Dear User,

You have requested to reset your password. Your password reset OTP is: %s

This OTP will expire in 10 minutes. Please do not share this code with anyone.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Best regards,
Your App Team
    `, otp)
	return sendEmail("SendPasswordResetOTPEmail", email, subject, body)
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
	return sendEmail("SendTemporaryPasswordEmail", email, subject, body)
}

// SendAdminInviteEmail sends a tailored invite email for admin users with login URL, username, and temp password.
func SendAdminInviteEmail(email, username, tenantDomain, tempPassword string) error {
	// Build login URL from tenant domain; fall back to base URL if tenant domain missing.
	loginURL := strings.TrimSpace(tenantDomain)
	if loginURL == "" {
		loginURL = strings.TrimSpace(config.AppConfig.BaseURL)
	}
	if loginURL != "" && !strings.HasPrefix(strings.ToLower(loginURL), "http") {
		loginURL = "https://" + loginURL
	}

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
	return sendEmail("SendAdminInviteEmail", email, subject, body)
}

// SendAccountDeactivationEmail sends notification when user account is deactivated
func SendAccountDeactivationEmail(email string) error {
	subject := "Account Deactivation Notice"
	body := `
Dear User,

Your account has been deactivated by an administrator.

You will no longer be able to access the system with this account. If you believe this was done in error or if you need to regain access, please contact your system administrator.

If you have any questions or concerns, please reach out to our support team.

Best regards,
Your Security Team
    `
	return sendEmail("SendAccountDeactivationEmail", email, subject, body)
}

// SendNewUserRegistrationNotificationEmail sends a notification to the tenant owner when a new user registers.
func SendNewUserRegistrationNotificationEmail(ownerEmail, userName, userEmail, tenantDomain string) error {
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
`, userName, userEmail, tenantDomain, time.Now().UTC().Format(time.RFC1123))
	return sendEmail("SendNewUserRegistrationNotificationEmail", ownerEmail, subject, body)
}
