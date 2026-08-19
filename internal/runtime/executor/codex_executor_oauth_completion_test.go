package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// TestCodexExecutorOAuthCompletionOverrideTransport exercises the OAuth
// completion override through the real HTTP transport: the override endpoint
// receives exactly one request, executor-managed credential and
// representation headers win over harness input, and harness headers still
// override configured defaults for ordinary header names.
func TestCodexExecutorOAuthCompletionOverrideTransport(t *testing.T) {
	var attempts int32
	var gotPath, gotAuthorization, gotAccept, gotSleevToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotSleevToken = r.Header.Get("sleev-token")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n"))
	}))
	defer server.Close()

	cfg := &config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}
	cfg.OAuth = map[string]config.OAuthProviderConfig{
		"codex": {
			BaseURL: server.URL,
			Headers: map[string]string{"sleev-token": "default-token"},
		},
	}
	executor := NewCodexExecutor(cfg)
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth},
		Metadata:   map[string]any{"access_token": "provider-token"},
	}
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.4",
		Payload: []byte(`{"model":"gpt-5.4","stream":true,"input":[{"type":"message","role":"user","content":"hi"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Stream:       true,
		Metadata:     map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"},
		Headers: http.Header{
			"Authorization": {"Bearer harness-token"},
			"Accept":        {"application/json"},
			"Sleev-Token":   {"harness-token"},
		},
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for range result.Chunks {
	}

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("upstream attempts = %d, want exactly 1", got)
	}
	if gotPath != "/responses" {
		t.Fatalf("upstream path = %q, want /responses on the override endpoint", gotPath)
	}
	if gotAuthorization != "Bearer provider-token" {
		t.Fatalf("Authorization = %q, want provider credential, not harness value", gotAuthorization)
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("Accept = %q, want executor-managed text/event-stream", gotAccept)
	}
	if gotSleevToken != "harness-token" {
		t.Fatalf("sleev-token = %q, want harness value overriding configured default", gotSleevToken)
	}
}
