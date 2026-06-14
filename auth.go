package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/adrg/xdg"
	"github.com/urfave/cli/v3"
)

var ErrNoAuthSession = errors.New("no auth session found")

type AuthSession struct {
	AuthMethod       string                   `json:"auth_method,omitempty"`
	DID              syntax.DID               `json:"did"`
	Password         string                   `json:"password,omitempty"`
	AccessToken      string                   `json:"access_token,omitempty"`
	RefreshToken     string                   `json:"session_token,omitempty"`
	PDS              string                   `json:"pds,omitempty"`
	OAuthClientID    string                   `json:"oauth_client_id,omitempty"`
	OAuthCallbackURL string                   `json:"oauth_callback_url,omitempty"`
	OAuth            *oauth.ClientSessionData `json:"oauth,omitempty"`
}

const authMethodOAuth = "oauth"

type goatOAuthStore struct {
	lk          sync.Mutex
	requests    map[string]oauth.AuthRequestData
	clientID    string
	callbackURL string
}

func newGoatOAuthStore() *goatOAuthStore {
	return &goatOAuthStore{requests: make(map[string]oauth.AuthRequestData)}
}

func (s *goatOAuthStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	sess, err := loadAuthSessionFile()
	if err != nil {
		return nil, err
	}
	if sess.AuthMethod != authMethodOAuth || sess.OAuth == nil {
		return nil, ErrNoAuthSession
	}
	if sess.OAuth.AccountDID != did || sess.OAuth.SessionID != sessionID {
		return nil, fmt.Errorf("OAuth session not found: %s/%s", did, sessionID)
	}
	data := *sess.OAuth
	return &data, nil
}

func (s *goatOAuthStore) SaveSession(ctx context.Context, data oauth.ClientSessionData) error {
	sess := AuthSession{
		AuthMethod:       authMethodOAuth,
		DID:              data.AccountDID,
		PDS:              data.HostURL,
		OAuthClientID:    s.clientID,
		OAuthCallbackURL: s.callbackURL,
		OAuth:            &data,
	}
	return persistAuthSession(&sess)
}

func (s *goatOAuthStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	return wipeAuthSession()
}

func (s *goatOAuthStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	s.lk.Lock()
	defer s.lk.Unlock()
	info, ok := s.requests[state]
	if !ok {
		return nil, fmt.Errorf("OAuth request info not found: %s", state)
	}
	return &info, nil
}

func (s *goatOAuthStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	s.lk.Lock()
	defer s.lk.Unlock()
	if _, ok := s.requests[info.State]; ok {
		return fmt.Errorf("OAuth request info already saved: %s", info.State)
	}
	s.requests[info.State] = info
	return nil
}

func (s *goatOAuthStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	s.lk.Lock()
	defer s.lk.Unlock()
	delete(s.requests, state)
	return nil
}

func oauthClientApp(callbackURL string, store oauth.ClientAuthStore) *oauth.ClientApp {
	config := oauth.NewLocalhostConfig(callbackURL, []string{"atproto", "transition:generic"})
	config.UserAgent = userAgentString()
	if s, ok := store.(*goatOAuthStore); ok {
		s.clientID = config.ClientID
		s.callbackURL = config.CallbackURL
	}
	return oauth.NewClientApp(&config, store)
}

func oauthClientAppForSession(sess *AuthSession, store *goatOAuthStore) *oauth.ClientApp {
	callbackURL := sess.OAuthCallbackURL
	if callbackURL == "" {
		callbackURL = "http://127.0.0.1/oauth/callback"
	}
	app := oauthClientApp(callbackURL, store)
	if sess.OAuthClientID != "" {
		app.Config.ClientID = sess.OAuthClientID
		store.clientID = sess.OAuthClientID
	}
	store.callbackURL = callbackURL
	return app
}

func persistAuthSession(sess *AuthSession) error {

	fPath, err := xdg.StateFile("goat/auth-session.json")
	if err != nil {
		return err
	}

	f, err := os.OpenFile(fPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	authBytes, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	_, err = f.Write(authBytes)
	return err
}

func loadAuthSessionFile() (*AuthSession, error) {
	fPath, err := xdg.SearchStateFile("goat/auth-session.json")
	if err != nil {
		return nil, ErrNoAuthSession
	}

	fBytes, err := os.ReadFile(fPath)
	if err != nil {
		return nil, err
	}

	var sess AuthSession
	err = json.Unmarshal(fBytes, &sess)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func authRefreshCallback(ctx context.Context, data atclient.PasswordSessionData) {
	fmt.Println("auth refresh callback")
	sess, _ := loadAuthSessionFile()
	if sess == nil {
		sess = &AuthSession{}
	}

	sess.DID = data.AccountDID
	sess.AccessToken = data.AccessToken
	sess.RefreshToken = data.RefreshToken
	sess.PDS = data.Host

	if err := persistAuthSession(sess); err != nil {
		slog.Warn("failed to save refreshed auth session data", "err", err)
	}
}

func loginOrLoadAuthClient(ctx context.Context, cmd *cli.Command) (*atclient.APIClient, error) {

	// if user/pass provided in env vars, login as emphemeral session with those
	username := cmd.String("username")
	password := cmd.String("password")
	if username != "" && password != "" {
		dir := configDirectory(cmd.String("plc-host"))
		atid, err := syntax.ParseAtIdentifier(username)
		if err != nil {
			return nil, err
		}
		return atclient.LoginWithPassword(ctx, dir, atid, password, "", nil)
	}

	// otherwise try loading from disk
	return loadAuthClient(ctx, cmd)
}

func loadAuthClient(ctx context.Context, cmd *cli.Command) (*atclient.APIClient, error) {

	sess, err := loadAuthSessionFile()
	if err != nil {
		return nil, err
	}
	if sess.AuthMethod == authMethodOAuth || sess.OAuth != nil {
		if sess.OAuth == nil {
			return nil, fmt.Errorf("OAuth session data missing")
		}
		store := newGoatOAuthStore()
		app := oauthClientAppForSession(sess, store)
		oauthSess, err := app.ResumeSession(ctx, sess.OAuth.AccountDID, sess.OAuth.SessionID)
		if err != nil {
			return nil, err
		}
		client := oauthSess.APIClient()
		_, err = comatproto.ServerGetSession(ctx, client)
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	// first try to resume session
	client := atclient.ResumePasswordSession(atclient.PasswordSessionData{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		AccountDID:   sess.DID,
		Host:         sess.PDS,
	}, authRefreshCallback)

	// check that auth is working
	_, err = comatproto.ServerGetSession(ctx, client)
	if nil == err {
		return client, nil
	}

	// otherwise try new auth session using saved password
	dir := configDirectory(cmd.String("plc-host"))
	return atclient.LoginWithPassword(ctx, dir, sess.DID.AtIdentifier(), sess.Password, "", authRefreshCallback)
}

func wipeAuthSession() error {

	fPath, err := xdg.SearchStateFile("goat/auth-session.json")
	if err != nil {
		fmt.Printf("no auth session found (already logged out)\n")
		return nil
	}
	return os.Remove(fPath)
}
