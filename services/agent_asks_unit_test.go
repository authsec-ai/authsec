package services

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/slackapp"
)

func askInput() AskInput {
	return AskInput{AboutKind: "agent", AboutID: uuid.NewString(), Question: " Retire it? ",
		Choices: []AskChoice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: " No "}}}
}

func TestValidateAskInput(t *testing.T) {
	now := time.Now()
	in := askInput()
	if err := ValidateAskInput(&in, now); err != nil {
		t.Fatal(err)
	}
	if in.Question != "Retire it?" || in.Choices[1].Label != "No" || in.Role != AskRoleResponder || in.Tier != 1 {
		t.Fatalf("not normalised: %+v", in)
	}
	bad := []func(*AskInput){
		func(a *AskInput) { a.AboutKind = "user" },
		func(a *AskInput) { a.AboutID = "" },
		func(a *AskInput) { a.Question = "  " },
		func(a *AskInput) { a.Question = strings.Repeat("x", 2001) },
		func(a *AskInput) { a.Choices = a.Choices[:1] },
		func(a *AskInput) { a.Choices[1].ID = "yes" },
		func(a *AskInput) { a.Choices[0].ID = "Has Space" },
		func(a *AskInput) { a.Choices[0].Label = "" },
		func(a *AskInput) { a.Severity = "critical" },
		func(a *AskInput) { a.Tier = 5 },
		func(a *AskInput) { a.Role = "boss" },
		func(a *AskInput) { a.ExternalDeadlineSource = "vendor SLA" },
		func(a *AskInput) { t := now.Add(time.Hour); a.ExternalDeadline = &t },
		func(a *AskInput) { t := now.Add(-time.Hour); a.ExternalDeadline, a.ExternalDeadlineSource = &t, "x" },
		func(a *AskInput) {
			t := now.Add(400 * 24 * time.Hour)
			a.ExternalDeadline, a.ExternalDeadlineSource = &t, "x"
		},
	}
	for i, f := range bad {
		in := askInput()
		f(&in)
		if err := ValidateAskInput(&in, now); err == nil {
			t.Errorf("case %d accepted: %+v", i, in)
		}
	}
	// The kind's tier is a floor.
	for kind, want := range map[string]int{"containment": 2, "gateway_call": 2, "remediation": 4, "alert": 1} {
		in := askInput()
		in.AboutKind = kind
		if err := ValidateAskInput(&in, now); err != nil || in.Tier != want {
			t.Errorf("%s: tier %d (%v), want %d", kind, in.Tier, err, want)
		}
	}
}

func TestAgentAskDueFromPolicyOrEarlierDeadline(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	p := DefaultAgentAskPolicy()
	for sev, h := range map[string]int{"high": 4, "medium": 24, "low": 72, "": 72} {
		due, src := AgentAskDue(p, sev, now, nil)
		if !due.Equal(now.Add(time.Duration(h)*time.Hour)) || src != "policy" {
			t.Errorf("%q: %s %s", sev, due, src)
		}
	}
	early := now.Add(time.Hour)
	if due, src := AgentAskDue(p, "low", now, &early); !due.Equal(early) || src != "external_deadline" {
		t.Errorf("earlier external: %s %s", due, src)
	}
	// A later external deadline never lengthens the policy.
	late := now.Add(100 * time.Hour)
	if due, src := AgentAskDue(p, "high", now, &late); !due.Equal(now.Add(4*time.Hour)) || src != "policy" {
		t.Errorf("later external: %s %s", due, src)
	}
}

func TestAgentAskPolicyLoosens(t *testing.T) {
	base := DefaultAgentAskPolicy().values()
	if AgentAskPolicyLoosens(base, base) {
		t.Fatal("no change loosens")
	}
	tight := base
	tight.DueHighHours, tight.ChannelWebhook = 2, true
	if AgentAskPolicyLoosens(base, tight) {
		t.Fatal("shorter due and a channel on is tightening")
	}
	for i, f := range []func(*agentAskPolicyValues){
		func(v *agentAskPolicyValues) { v.DueHighHours = 5 },
		func(v *agentAskPolicyValues) { v.DueLowHours = 100 },
		func(v *agentAskPolicyValues) { v.HoursPerStep = 8 },
		func(v *agentAskPolicyValues) { v.ChannelSlack = false },
		func(v *agentAskPolicyValues) { v.ChannelEmail = false },
	} {
		to := base
		f(&to)
		if !AgentAskPolicyLoosens(base, to) {
			t.Errorf("case %d does not loosen", i)
		}
	}
}

func TestAskStepUpLocalTierCheck(t *testing.T) {
	if askAnswerNeedsStepUp(1, AskChannelSlack) || askAnswerNeedsStepUp(4, AskChannelConsole) {
		t.Fatal("tier 1 from Slack and the console need no step-up")
	}
	if !askAnswerNeedsStepUp(2, AskChannelSlack) || !askAnswerNeedsStepUp(3, AskChannelSlack) {
		t.Fatal("tier 2+ from Slack needs step-up")
	}
}

func TestAgentAskButtonTokenBinds(t *testing.T) {
	n, a := uuid.New(), uuid.New()
	tok := agentAskButtonToken("s", n, a, 0, "yes")
	if len(tok) != 32 || tok != agentAskButtonToken("s", n, a, 0, "yes") {
		t.Fatal("token not stable")
	}
	for _, other := range []string{agentAskButtonToken("s2", n, a, 0, "yes"), agentAskButtonToken("s", uuid.New(), a, 0, "yes"),
		agentAskButtonToken("s", n, uuid.New(), 0, "yes"), agentAskButtonToken("s", n, a, 1, "yes"), agentAskButtonToken("s", n, a, 0, "no")} {
		if other == tok {
			t.Fatal("token ignores a bound field")
		}
	}
	msg := slackapp.BuildAsk(slackapp.Ask{Title: "t", Lines: []string{"q"}, Choices: []slackapp.LabeledValue{{Label: "Yes", Value: "v1"},
		{Label: "No", Value: "v2"}}, NotMineValue: "v3", Link: "https://x/asks/1"})
	var ids []string
	for _, b := range msg.Blocks {
		if b["type"] == "actions" {
			for _, e := range b["elements"].([]any) {
				ids = append(ids, e.(map[string]any)["action_id"].(string))
			}
		}
	}
	if strings.Join(ids, ",") != "ask_choice_0,ask_choice_1,ask_not_mine,open" {
		t.Fatalf("buttons %v", ids)
	}
	v, err := slackapp.DecodeButtonValue(slackapp.ButtonValue{Notification: n.String(), Digest: tok, Choice: "yes"}.Encode())
	if err != nil || v.Choice != "yes" || v.Digest != tok {
		t.Fatalf("button value %+v %v", v, err)
	}
}

func TestValidateAgentAskIntegrationConfig(t *testing.T) {
	cfg, err := ValidateAgentAskIntegrationConfig("jira", map[string]string{"site_url": "https://acme.atlassian.net/",
		"email": "bot@acme.com", "project_key": "SEC"})
	if err != nil || cfg["site_url"] != "https://acme.atlassian.net" || cfg["issue_type"] != "Task" || cfg["create_for"] != "asks" {
		t.Fatalf("%v %v", cfg, err)
	}
	for _, c := range []struct {
		p   string
		cfg map[string]string
	}{
		{"jira", map[string]string{"site_url": "http://acme.atlassian.net", "email": "a@b.c", "project_key": "SEC"}},
		{"jira", map[string]string{"site_url": "https://acme.atlassian.net", "email": "nope", "project_key": "SEC"}},
		{"jira", map[string]string{"site_url": "https://acme.atlassian.net", "email": "a@b.c", "project_key": "sec"}},
		{"jira", map[string]string{"site_url": "https://acme.atlassian.net", "email": "a@b.c", "project_key": "SEC", "token": "x"}},
		{"servicenow", map[string]string{"instance_url": "https://x.service-now.com"}},
		{"servicenow", map[string]string{"instance_url": "https://x.service-now.com", "username": "u", "create_for": "all"}},
		{"pagerduty", map[string]string{"region": "ap"}},
		{"opsgenie", map[string]string{"api_key": "k"}},
	} {
		if _, err := ValidateAgentAskIntegrationConfig(c.p, c.cfg); err == nil {
			t.Errorf("%s %v accepted", c.p, c.cfg)
		}
	}
	if cfg, err := ValidateAgentAskIntegrationConfig("opsgenie", nil); err != nil || cfg["region"] != "us" {
		t.Fatalf("opsgenie default %v %v", cfg, err)
	}
}

func TestAskNeededSpecs(t *testing.T) {
	for _, r := range []string{AskReasonDeletedAtSource, AskReasonDeciderLeft, AskReasonUnknownDeployer, "other"} {
		q, cs, sev, _ := askNeededSpec(r, map[string]any{"deployer": "arn:aws:iam::1:user/x", "user_id": uuid.New()})
		in := AskInput{AboutKind: "agent", AboutID: uuid.NewString(), Question: q, Choices: cs, Severity: sev}
		if err := ValidateAskInput(&in, time.Now()); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	if _, _, sev, _ := askNeededSpec(AskReasonUnknownDeployer, map[string]any{"deployer": "x"}); sev != "high" {
		t.Fatal("an unknown deployer is high severity")
	}
}
