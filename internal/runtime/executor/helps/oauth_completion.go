package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// OAuthCompletionBaseURL returns the configured completion endpoint for an
// incoming request, or fallback when the request is not eligible for an
// override.
func OAuthCompletionBaseURL(cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options, fallback string) string {
	override, ok := oauthCompletionConfig(cfg, auth, opts)
	if !ok || strings.TrimSpace(override.BaseURL) == "" {
		return fallback
	}
	return strings.TrimRight(strings.TrimSpace(override.BaseURL), "/")
}

// ApplyOAuthCompletionHeaders applies configured defaults and incoming harness
// headers to an OAuth completion request. Harness values take precedence over
// configured defaults, while credential, provider identity, and transport
// headers remain protected.
func ApplyOAuthCompletionHeaders(headers http.Header, cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options) {
	applyOAuthCompletionHeaders(headers, cfg, auth, opts, forwardOAuthCompletionHeader)
}

func ApplyOAuthCompletionWebsocketHeaders(headers http.Header, cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options) {
	applyOAuthCompletionHeaders(headers, cfg, auth, opts, forwardOAuthCompletionWebsocketHeader)
}

func applyOAuthCompletionHeaders(headers http.Header, cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options, forward func(string) bool) {
	override, ok := oauthCompletionConfig(cfg, auth, opts)
	if !ok {
		return
	}
	for name, value := range override.Headers {
		if !forward(name) {
			continue
		}
		headers.Set(name, value)
	}
	for name, values := range opts.Headers {
		if !forward(name) {
			continue
		}
		headers.Del(name)
		for _, value := range values {
			headers.Add(name, value)
		}
	}
}

func forwardOAuthCompletionWebsocketHeader(name string) bool {
	switch http.CanonicalHeaderKey(strings.TrimSpace(name)) {
	case "Openai-Beta", "Origin", "Originator", "X-Grok-Conv-Id":
		return false
	default:
		return forwardOAuthCompletionHeader(name)
	}
}

func forwardOAuthCompletionHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
	// WebSocket headers are managed by the transport dialer; forwarding
	// caller-supplied ones would corrupt the upgrade handshake.
	if strings.HasPrefix(canonical, "Sec-Websocket-") {
		return false
	}
	switch canonical {
	case "Authorization", "X-Api-Key", "Accept", "Accept-Encoding", "Content-Type", "Host", "Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Cookie", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Content-Encoding", "Chatgpt-Account-Id", "X-Grok-Conv-Id", "Session-Id", "Session_id", "Thread-Id", "X-Client-Request-Id", "X-Codex-Turn-Metadata", "X-Codex-Window-Id":
		// Credentials, provider identity, and representation headers (Accept,
		// Accept-Encoding, Content-Type) must keep the values the executor set,
		// since authentication and response decoding depend on them.
		return false
	default:
		if strings.EqualFold(canonical, "Conversation_id") || strings.EqualFold(canonical, "Session_id") {
			return false
		}
		return strings.TrimSpace(name) != ""
	}
}

func oauthCompletionConfig(cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options) (config.OAuthProviderConfig, bool) {
	if cfg == nil || auth == nil || auth.AuthKind() != cliproxyauth.AuthKindOAuth || opts.Metadata == nil {
		return config.OAuthProviderConfig{}, false
	}
	requestPath, ok := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	if !ok || strings.TrimSpace(requestPath) == "" {
		return config.OAuthProviderConfig{}, false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	for name, override := range cfg.OAuth {
		if strings.EqualFold(strings.TrimSpace(name), provider) {
			return override, true
		}
	}
	return config.OAuthProviderConfig{}, false
}
