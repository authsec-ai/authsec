// Package slacktest is an in-memory Slack Web API (slackapp.API) for tests:
// no network, every call recorded.
package slacktest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/internal/slackapp"
)

// Post is one chat.postMessage.
type Post struct {
	Token   string
	Channel string
	TS      string
	Message slackapp.Message
}

// Response is one response_url post.
type Response struct {
	URL     string
	Message slackapp.Message
}

// Install is what an OAuth code exchanges to.
type Install struct {
	ClientID string
	Result   slackapp.OAuthResult
}

// Fake implements slackapp.API.
type Fake struct {
	mu        sync.Mutex
	installs  map[string]Install // code -> install (single use)
	users     map[string]slackapp.User
	Posts     []Post
	Responses []Response
	Revoked   []string
	Exchanges []string // codes exchanged
	// PostErr fails chat.postMessage (e.g. &slackapp.APIError{Code: "not_in_channel"}).
	PostErr error
	seq     int
}

// New is an empty fake.
func New() *Fake {
	return &Fake{installs: map[string]Install{}, users: map[string]slackapp.User{}}
}

// AddInstall makes code exchange to r for clientID.
func (f *Fake) AddInstall(code, clientID string, r slackapp.OAuthResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installs[code] = Install{ClientID: clientID, Result: r}
}

// AddUser registers a Slack user.
func (f *Fake) AddUser(u slackapp.User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.ID] = u
}

// SetPostErr sets PostErr.
func (f *Fake) SetPostErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PostErr = err
}

// OAuthV2Access implements slackapp.API.
func (f *Fake) OAuthV2Access(_ context.Context, clientID, clientSecret, code, _ string) (*slackapp.OAuthResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Exchanges = append(f.Exchanges, code)
	in, ok := f.installs[code]
	if !ok || clientSecret == "" {
		return nil, &slackapp.APIError{Method: "oauth.v2.access", Code: "invalid_code"}
	}
	if in.ClientID != clientID {
		return nil, &slackapp.APIError{Method: "oauth.v2.access", Code: "invalid_client_id"}
	}
	delete(f.installs, code)
	r := in.Result
	return &r, nil
}

// PostMessage implements slackapp.API.
func (f *Fake) PostMessage(_ context.Context, token, channel string, msg slackapp.Message) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.PostErr != nil {
		return "", "", f.PostErr
	}
	if token == "" {
		return "", "", &slackapp.APIError{Method: "chat.postMessage", Code: "not_authed"}
	}
	f.seq++
	ts := fmt.Sprintf("1700000000.%06d", f.seq)
	ch := channel
	if strings.HasPrefix(channel, "U") || strings.HasPrefix(channel, "W") {
		ch = "D" + channel // the app's DM with the user
	}
	f.Posts = append(f.Posts, Post{Token: token, Channel: channel, TS: ts, Message: msg})
	return ts, ch, nil
}

// UsersInfo implements slackapp.API.
func (f *Fake) UsersInfo(_ context.Context, token, userID string) (*slackapp.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return nil, &slackapp.APIError{Method: "users.info", Code: "user_not_found"}
	}
	return &u, nil
}

// LookupByEmail implements slackapp.API.
func (f *Fake) LookupByEmail(_ context.Context, token, email string) (*slackapp.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Email, email) {
			cp := u
			return &cp, nil
		}
	}
	return nil, &slackapp.APIError{Method: "users.lookupByEmail", Code: "users_not_found"}
}

// Respond implements slackapp.API.
func (f *Fake) Respond(_ context.Context, responseURL string, msg slackapp.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Responses = append(f.Responses, Response{URL: responseURL, Message: msg})
	return nil
}

// AuthRevoke implements slackapp.API.
func (f *Fake) AuthRevoke(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Revoked = append(f.Revoked, token)
	return nil
}

// PostsTo returns the posts to channel.
func (f *Fake) PostsTo(channel string) []Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Post
	for _, p := range f.Posts {
		if p.Channel == channel {
			out = append(out, p)
		}
	}
	return out
}

// LastResponse is the newest response_url post ("" text when none).
func (f *Fake) LastResponse() Response {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Responses) == 0 {
		return Response{}
	}
	return f.Responses[len(f.Responses)-1]
}

// ResponseCount is the number of response_url posts.
func (f *Fake) ResponseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Responses)
}
