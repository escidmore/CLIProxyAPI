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
// configured defaults, while credential and transport headers remain protected.
func ApplyOAuthCompletionHeaders(headers http.Header, cfg *config.Config, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options) {
	override, ok := oauthCompletionConfig(cfg, auth, opts)
	if !ok {
		return
	}
	for name, value := range override.Headers {
		if !forwardOAuthCompletionHeader(name) {
			continue
		}
		headers.Set(name, value)
	}
	for name, values := range opts.Headers {
		if !forwardOAuthCompletionHeader(name) {
			continue
		}
		headers.Del(name)
		for _, value := range values {
			headers.Add(name, value)
		}
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
	case "Authorization", "X-Api-Key", "Accept", "Accept-Encoding", "Content-Type", "Host", "Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Cookie", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Content-Encoding":
		// Credentials stay with the executor, and representation headers
		// (Accept, Accept-Encoding, Content-Type) must keep the values the
		// executor set, since response decoding depends on them.
		return false
	default:
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
