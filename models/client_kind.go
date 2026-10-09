package models

// OAuth client kinds. The column already carried these values as bare strings in
// several places; naming them keeps a typo from silently creating a client the
// claim dialog cannot see (it filters on 'agent').
const (
	ClientKindHumanApp = "human_app"
	ClientKindAgent    = "agent"
	ClientKindM2M      = "m2m"
	ClientKindCLI      = "cli"
)

// ValidClientKinds returns the kinds the schema allows.
func ValidClientKinds() []string {
	return []string{ClientKindHumanApp, ClientKindAgent, ClientKindM2M, ClientKindCLI}
}
