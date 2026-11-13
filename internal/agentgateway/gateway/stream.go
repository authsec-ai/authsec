package gateway

import (
	"bytes"
	"io"
	"net/http"
)

// sseParser receives a Server-Sent Events stream in arbitrary chunks and
// calls onEvent with each event's data (its data lines joined by "\n"). It
// keeps at most max bytes of a pending line or event; longer ones are
// skipped, never buffered without bound. It only ever sees bytes on their
// way to the agent and keeps nothing after onEvent returns.
type sseParser struct {
	line    []byte
	data    []byte
	max     int
	skip    bool
	lastCR  bool
	onEvent func(data []byte)
}

func newSSEParser(max int, onEvent func([]byte)) *sseParser {
	return &sseParser{max: max, onEvent: onEvent}
}

func (p *sseParser) Write(b []byte) (int, error) {
	for _, c := range b {
		if c == '\n' && p.lastCR {
			p.lastCR = false
			continue
		}
		p.lastCR = c == '\r'
		if c == '\n' || c == '\r' {
			p.endLine()
			continue
		}
		if p.skip {
			continue
		}
		if len(p.line) >= p.max {
			p.skip, p.line = true, p.line[:0]
			continue
		}
		p.line = append(p.line, c)
	}
	return len(b), nil
}

func (p *sseParser) endLine() {
	if p.skip {
		p.skip, p.line, p.data = false, p.line[:0], p.data[:0]
		return
	}
	line := p.line
	p.line = p.line[:0]
	if len(line) == 0 {
		if len(p.data) > 0 && p.onEvent != nil {
			p.onEvent(p.data)
		}
		p.data = p.data[:0]
		return
	}
	if v, ok := bytes.CutPrefix(line, []byte("data:")); ok {
		v = bytes.TrimPrefix(v, []byte(" "))
		if len(p.data)+len(v)+1 > p.max {
			p.data = p.data[:0]
			return
		}
		if len(p.data) > 0 {
			p.data = append(p.data, '\n')
		}
		p.data = append(p.data, v...)
	}
}

// Close dispatches a final event not followed by a blank line.
func (p *sseParser) Close() {
	if len(p.line) > 0 {
		p.endLine()
	}
	if len(p.data) > 0 && p.onEvent != nil {
		p.onEvent(p.data)
	}
	p.data = p.data[:0]
}

// boundedBuffer keeps the first max bytes written to it; Overflow reports
// whether more arrived (the content is then not parsed).
type boundedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.overflow {
		return len(p), nil
	}
	if b.buf.Len()+len(p) > b.max {
		b.overflow = true
		b.buf.Reset()
		return len(p), nil
	}
	return b.buf.Write(p)
}

// hopHeaders are not forwarded (RFC 9110 §7.6.1).
var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// copyResponse writes the upstream response to the agent, flushing after
// every read so streams (SSE) are not held back; tee, when set, sees the
// same bytes.
func copyResponse(w http.ResponseWriter, resp *http.Response, tee io.Writer) error {
	for k, vs := range resp.Header {
		if hopHeaders[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if tee != nil {
				_, _ = tee.Write(buf[:n])
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func isEventStream(ct string) bool {
	return len(ct) >= len("text/event-stream") && bytes.EqualFold([]byte(ct[:len("text/event-stream")]), []byte("text/event-stream"))
}
