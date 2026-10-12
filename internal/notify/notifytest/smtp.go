// Package notifytest is an in-process SMTP relay that records every session,
// for tests of internal/notify and its callers. It speaks just enough ESMTP
// for net/smtp.SendMail: a 220 greeting, EHLO advertising AUTH PLAIN (no
// STARTTLS, so PLAIN auth is allowed only because the relay is 127.0.0.1),
// AUTH, MAIL, RCPT, DATA, RSET, NOOP and QUIT.
package notifytest

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
)

// Session is one recorded SMTP conversation.
type Session struct {
	// Commands are the client's command lines in order (AUTH's credentials
	// included verbatim: it is a test relay).
	Commands []string
	// Auth is the decoded AUTH PLAIN response (authzid \x00 user \x00 pass).
	Auth string
	From string
	To   []string
	// Data is the message exactly as received, dot-unstuffed, without the
	// terminating "." line.
	Data []byte
}

// SMTPRecorder is a recording relay listening on 127.0.0.1.
type SMTPRecorder struct {
	ln net.Listener

	mu       sync.Mutex
	sessions []Session
	// RejectData, when set, answers DATA's end with 554 (a delivery failure).
	rejectData bool
	wg         sync.WaitGroup
}

// NewSMTPRecorder starts a relay on a free 127.0.0.1 port.
func NewSMTPRecorder() (*SMTPRecorder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &SMTPRecorder{ln: ln}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

// Host and Port are where the relay listens.
func (r *SMTPRecorder) Host() string { return "127.0.0.1" }
func (r *SMTPRecorder) Port() string {
	_, p, _ := net.SplitHostPort(r.ln.Addr().String())
	return p
}

// SetRejectData makes later sessions fail at end of DATA (554).
func (r *SMTPRecorder) SetRejectData(v bool) {
	r.mu.Lock()
	r.rejectData = v
	r.mu.Unlock()
}

// Sessions returns the completed sessions so far.
func (r *SMTPRecorder) Sessions() []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Session(nil), r.sessions...)
}

// Close stops the relay.
func (r *SMTPRecorder) Close() {
	_ = r.ln.Close()
	r.wg.Wait()
}

func (r *SMTPRecorder) serve() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handle(c)
		}()
	}
}

func (r *SMTPRecorder) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	say := func(s string) {
		_, _ = w.WriteString(s + "\r\n")
		_ = w.Flush()
	}
	var s Session
	say("220 notifytest ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.Commands = append(s.Commands, line)
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			_, _ = w.WriteString("250-notifytest\r\n250-8BITMIME\r\n250 AUTH PLAIN\r\n")
			_ = w.Flush()
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) == 3 {
				raw, _ := base64.StdEncoding.DecodeString(parts[2])
				s.Auth = string(raw)
			}
			say("235 2.7.0 Authentication successful")
		case "MAIL":
			s.From = strings.TrimSuffix(strings.TrimPrefix(line[len("MAIL FROM:"):], "<"), ">")
			if i := strings.Index(s.From, ">"); i >= 0 {
				s.From = s.From[:i]
			}
			say("250 2.1.0 OK")
		case "RCPT":
			to := strings.TrimPrefix(line[len("RCPT TO:"):], "<")
			if i := strings.Index(to, ">"); i >= 0 {
				to = to[:i]
			}
			s.To = append(s.To, to)
			say("250 2.1.5 OK")
		case "DATA":
			say("354 End data with <CR><LF>.<CR><LF>")
			var data []byte
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				if strings.HasPrefix(l, "..") {
					l = l[1:]
				}
				data = append(data, l...)
			}
			s.Data = data
			r.mu.Lock()
			reject := r.rejectData
			if !reject {
				r.sessions = append(r.sessions, s)
			}
			r.mu.Unlock()
			if reject {
				say("554 5.0.0 Rejected by notifytest")
			} else {
				say("250 2.0.0 OK queued")
			}
			s = Session{Commands: s.Commands}
		case "RSET":
			s = Session{Commands: s.Commands}
			say("250 OK")
		case "NOOP":
			say("250 OK")
		case "QUIT":
			say("221 Bye")
			return
		default:
			say("502 Command not implemented")
		}
	}
}
