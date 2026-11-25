package monitoring

import "testing"

func TestClassifyAuditRecord(t *testing.T) {
	cases := []struct {
		ev   AuditEvent
		want string
	}{
		{AuditEvent{Action: "admin_login_failure", Resource: "authentication"}, AuditClassAuth},
		{AuditEvent{Action: "mfa_verify"}, AuditClassAuth},
		{AuditEvent{Action: "governance.export_bundle", Method: "POST"}, AuditClassExport},
		{AuditEvent{Action: "access_request_approved", Resource: "access_request", Method: "POST"}, AuditClassAccessDecision},
		{AuditEvent{Action: "application_connection_denied", Method: "POST"}, AuditClassAccessDecision},
		{AuditEvent{Action: "application_updated", Method: "PUT"}, AuditClassAdminChange},
		{AuditEvent{Action: "agent_gateway.revoke", Method: "POST", UserID: "u"}, AuditClassAdminChange},
		{AuditEvent{Action: "sync", UserID: "system"}, AuditClassDefault},
		{AuditEvent{}, AuditClassDefault},
	}
	for _, c := range cases {
		if got := ClassifyAuditRecord(&c.ev); got != c.want {
			t.Errorf("%q/%q: %s, want %s", c.ev.Action, c.ev.Method, got, c.want)
		}
	}
}

// Without a database the write fails loudly (an error and the metric),
// never silently.
func TestWriteWithoutDatabaseReturnsError(t *testing.T) {
	l := &AuditLogger{}
	ev := &AuditEvent{Action: "thing.update", Method: "PUT"}
	if err := l.Write(ev); err == nil {
		t.Fatal("a write with no database must return an error")
	}
	if ev.RecordClass != AuditClassAdminChange || ev.Timestamp.IsZero() {
		t.Fatalf("event not prepared: %+v", ev)
	}
}
