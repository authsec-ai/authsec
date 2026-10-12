package notify

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SMTPConfig is the relay AuthSec sends through (config.AppConfig's SMTP*
// fields in production).
type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	// FromName is the From: display name; optional.
	FromName string
}

// Complete reports whether every field a send needs is set.
func (c SMTPConfig) Complete() bool {
	return c.Host != "" && c.Port != "" && c.User != "" && c.Password != ""
}

// FromHeader is the From: header value: "Name <user>" when a display name is
// configured, else the bare user. The From domain must be the one whose
// SPF/DKIM the relay signs for (utils/otp.go's DMARC note).
func (c SMTPConfig) FromHeader() string {
	if fromName := strings.TrimSpace(c.FromName); fromName != "" {
		return fmt.Sprintf("%s <%s>", fromName, c.User)
	}
	return c.User
}

// ErrSMTPNotConfigured is returned when the relay configuration is
// incomplete. Its text is the legacy warning sender's, unchanged.
var ErrSMTPNotConfigured = errors.New("SMTP configuration is incomplete")

// BuildEmail assembles the RFC 5322 message handed to the relay: From, To,
// Subject, Date, Message-ID, MIME-Version and an 8-bit text/plain body, CRLF
// line ends. It is the one place the header set is defined (Date and From
// are REQUIRED by RFC 5322 §3.6; without them Gmail and Outlook drop mail
// the relay accepted), and utils.buildEmailMessage delegates to it.
func BuildEmail(from, to, subject, body, date, messageID string) []byte {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
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

// NewMessageID is a fresh Message-ID in AuthSec's domain.
func NewMessageID() string { return fmt.Sprintf("<%s@authsec.ai>", uuid.NewString()) }

// EmailDate is the Date: header value for t (RFC 1123 with a numeric zone,
// in UTC).
func EmailDate(t time.Time) string { return t.UTC().Format(time.RFC1123Z) }

// SMTP sends email through the configured relay with PLAIN auth
// (net/smtp.SendMail: STARTTLS when the relay offers it).
type SMTP struct {
	// Config returns the relay configuration at send time, so a
	// configuration change needs no restart. Required.
	Config func() SMTPConfig
	// SendMail is net/smtp.SendMail unless replaced (tests).
	SendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	// Now and MessageID make the Date and Message-ID headers deterministic in
	// tests; nil means time.Now and NewMessageID.
	Now       func() time.Time
	MessageID func() string
}

// Send delivers m (ChannelEmail) to m.To. net/smtp has no context: ctx is
// not consulted once the dial starts. Errors from the relay are returned
// unwrapped, as the legacy sender returned them.
func (s *SMTP) Send(_ context.Context, m Message) error {
	if m.Channel != ChannelEmail {
		return fmt.Errorf("SMTP sender got a %s message", m.Channel)
	}
	if s == nil || s.Config == nil {
		return ErrSMTPNotConfigured
	}
	cfg := s.Config()
	if !cfg.Complete() {
		return ErrSMTPNotConfigured
	}
	now, mid := time.Now, NewMessageID
	if s.Now != nil {
		now = s.Now
	}
	if s.MessageID != nil {
		mid = s.MessageID
	}
	send := smtp.SendMail
	if s.SendMail != nil {
		send = s.SendMail
	}
	id := mid()
	msg := BuildEmail(cfg.FromHeader(), m.To, m.Subject, string(m.Body), EmailDate(now()), id)
	auth := smtp.PlainAuth("", cfg.User, cfg.Password, cfg.Host)
	return send(fmt.Sprintf("%s:%s", cfg.Host, cfg.Port), auth, cfg.User, []string{m.To}, msg)
}
