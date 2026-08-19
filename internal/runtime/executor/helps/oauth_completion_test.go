package helps

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestOAuthCompletionOverridesOnlyIncomingOAuthRequests(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth = map[string]config.OAuthProviderConfig{
		"codex": {
			BaseURL: "https://sleev.example/",
			Headers: map[string]string{
				"sleev-token":    "default-token",
				"sleev-provider": "codex",
				"empty-header":   "",
			},
		},
	}
	oauth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth},
	}
	incoming := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"},
		Headers: http.Header{
			"Authorization":          {"harness-authorization"},
			"ChatGPT-Account-ID":     {"harness-account-id"},
			"X-Api-Key":              {"harness-api-key"},
			"Accept":                 {"application/json"},
			"Accept-Encoding":        {"gzip"},
			"Proxy-Authenticate":     {"harness-proxy-authenticate"},
			"Proxy-Authorization":    {"harness-proxy-authorization"},
			"Cookie":                 {"session=secret"},
			"Keep-Alive":             {"timeout=5"},
			"Te":                     {"trailers"},
			"Trailer":                {"X-Request-Trailer"},
			"Sec-WebSocket-Protocol": {"chat"},
			"sleev-token":            {"harness-token"},
			"sleev-extra":            {"harness-value"},
		},
	}

	if got := OAuthCompletionBaseURL(cfg, oauth, incoming, "https://provider.example"); got != "https://sleev.example" {
		t.Fatalf("OAuthCompletionBaseURL() = %q, want override", got)
	}
	headers := http.Header{
		"Authorization":      {"provider-authorization"},
		"ChatGPT-Account-ID": {"provider-account-id"},
	}
	ApplyOAuthCompletionHeaders(headers, cfg, oauth, incoming)
	if got := headers.Get("sleev-token"); got != "harness-token" {
		t.Fatalf("sleev-token = %q, want harness-token", got)
	}
	if got := headers.Get("sleev-extra"); got != "harness-value" {
		t.Fatalf("sleev-extra = %q, want harness-value", got)
	}
	if got := headers.Get("Authorization"); got != "provider-authorization" {
		t.Fatalf("Authorization = %q, want provider-authorization", got)
	}
	for _, blocked := range []string{"X-Api-Key", "ChatGPT-Account-ID", "Accept", "Accept-Encoding", "Proxy-Authenticate", "Proxy-Authorization", "Cookie", "Keep-Alive", "Te", "Trailer", "Sec-WebSocket-Protocol"} {
		if got := headers.Get(blocked); got != "" {
			t.Fatalf("%s = %q, want blocked from harness passthrough", blocked, got)
		}
	}
	if got := headers.Get("empty-header"); got != "" {
		t.Fatalf("empty-header = %q, want empty value", got)
	}

	for name, testCase := range map[string]struct {
		auth *cliproxyauth.Auth
		opts cliproxyexecutor.Options
	}{
		"non-oauth": {
			auth: &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindAPIKey}},
			opts: incoming,
		},
		"non-incoming": {
			auth: oauth,
			opts: cliproxyexecutor.Options{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fallback := "https://provider.example"
			if got := OAuthCompletionBaseURL(cfg, testCase.auth, testCase.opts, fallback); got != fallback {
				t.Fatalf("OAuthCompletionBaseURL() = %q, want fallback", got)
			}
			headers := http.Header{}
			ApplyOAuthCompletionHeaders(headers, cfg, testCase.auth, testCase.opts)
			if got := headers.Get("sleev-token"); got != "" {
				t.Fatalf("sleev-token = %q, want no override", got)
			}
		})
	}
}

func TestOAuthCompletionWebsocketHeadersProtectHandshakeControls(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth = map[string]config.OAuthProviderConfig{
		"codex": {Headers: map[string]string{"sleev-token": "default-token", "OpenAI-Beta": "configured-beta", "Origin": "configured-origin", "Originator": "configured-originator"}},
	}
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth},
	}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"},
		Headers: http.Header{
			"OpenAI-Beta":    {"caller-beta"},
			"Origin":         {"caller-origin"},
			"Originator":     {"caller-originator"},
			"X-Grok-Conv-Id": {"caller-session"},
			"sleev-token":    {"harness-token"},
		},
	}
	headers := http.Header{}
	headers.Set("OpenAI-Beta", "responses_websockets=2026-01-01")
	headers.Set("Origin", "provider-origin")
	headers.Set("Originator", "codex")
	headers.Set("X-Grok-Conv-Id", "session-a")

	ApplyOAuthCompletionWebsocketHeaders(headers, cfg, auth, opts)
	for name, want := range map[string]string{
		"OpenAI-Beta":    "responses_websockets=2026-01-01",
		"Origin":         "provider-origin",
		"Originator":     "codex",
		"X-Grok-Conv-Id": "session-a",
		"sleev-token":    "harness-token",
	} {
		if got := headers.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
