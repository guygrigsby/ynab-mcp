package ynaboauth

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxResponseBytes   = 32 << 10
	maxRequestBytes    = 32 << 10
	maxLifetimeSeconds = 24 * 60 * 60 // Conservative connector policy; YNAB documents two hours.
)

type credentialTransport struct{ base http.RoundTripper }

// RoundTrip is the final credential egress boundary. Even programming mistakes
// in this package cannot turn it into an arbitrary method/host client.
func (t *credentialTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodPost || request.URL.String() != tokenURL || request.Host != "" && request.Host != "app.ynab.com" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Content-Encoding") != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Body == nil {
		if request != nil && request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, ErrTokenRequestFailed
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	_ = request.Body.Close()
	if err != nil || len(body) > maxRequestBytes || !validTokenRequest(body) {
		return nil, ErrTokenRequestFailed
	}
	request = request.Clone(request.Context())
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = nil // Credential requests are not replayable.
	request.Close = true
	request.Header.Del("Idempotency-Key")
	request.Header.Del("X-Idempotency-Key")
	request.Header.Set("Accept", "application/json")
	response, err := t.base.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrTokenRequestFailed
	}
	if response == nil || response.Body == nil {
		return nil, ErrInvalidResponse
	}
	defer response.Body.Close()
	// Reject every redirect before net/http can follow it or expose Location.
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		return nil, ErrTokenRequestFailed
	}
	if response.ContentLength > maxResponseBytes {
		return nil, ErrInvalidResponse
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return nil, ErrInvalidResponse
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, ErrInvalidResponse
	}
	fields, err := uniqueObject(body)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK || fields["error"] != nil {
		var code string
		if json.Unmarshal(fields["error"], &code) == nil && code == "invalid_grant" {
			return nil, ErrReconnectRequired
		}
		return nil, ErrTokenRequestFailed
	}
	validated, err := validateToken(fields)
	if err != nil {
		return nil, err
	}
	// Supply the maintained OAuth library only the validated token fields. Its
	// token.Raw therefore cannot retain unexpected provider content or errors.
	body, err = json.Marshal(validated)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	clean := *response
	clean.Header = http.Header{"Content-Type": {"application/json"}}
	clean.Body = io.NopCloser(bytes.NewReader(body))
	clean.ContentLength = int64(len(body))
	clean.Request = nil
	return &clean, nil
}

func validTokenRequest(body []byte) bool {
	form, err := url.ParseQuery(string(body))
	if err != nil || !visibleASCII(form.Get("client_id"), 1024) || !visibleASCII(form.Get("client_secret"), maxSecret) {
		return false
	}
	allowed := map[string]bool{"grant_type": true, "client_id": true, "client_secret": true}
	switch form.Get("grant_type") {
	case "authorization_code":
		allowed["code"], allowed["redirect_uri"], allowed["code_verifier"] = true, true, true
		if !visibleASCII(form.Get("code"), 4096) || !validCallback(form.Get("redirect_uri")) || !unreserved(form.Get("code_verifier"), 43, 128) {
			return false
		}
	case "refresh_token":
		allowed["refresh_token"] = true
		if !visibleASCII(form.Get("refresh_token"), maxSecret) {
			return false
		}
	default:
		return false
	}
	for key, values := range form {
		if !allowed[key] || len(values) != 1 {
			return false
		}
	}
	return true
}

type tokenPayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func validateToken(fields map[string]json.RawMessage) (tokenPayload, error) {
	var p tokenPayload
	if json.Unmarshal(fields["access_token"], &p.AccessToken) != nil || json.Unmarshal(fields["refresh_token"], &p.RefreshToken) != nil || json.Unmarshal(fields["token_type"], &p.TokenType) != nil || !visibleASCII(p.AccessToken, maxSecret) || !visibleASCII(p.RefreshToken, maxSecret) || !strings.EqualFold(p.TokenType, "bearer") {
		return p, ErrInvalidResponse
	}
	// Do not inherit oauth2's compatibility coercions of strings, null, floats
	// or oversized integers. Missing refresh_token is also invalid, including
	// during refresh: the library must not silently reuse an old credential.
	rawExpiry := string(fields["expires_in"])
	if rawExpiry == "" || strings.ContainsAny(rawExpiry, "\".eE+-") {
		return p, ErrInvalidResponse
	}
	var err error
	p.ExpiresIn, err = strconv.ParseInt(rawExpiry, 10, 64)
	if err != nil || p.ExpiresIn < 1 || p.ExpiresIn > maxLifetimeSeconds {
		return p, ErrInvalidResponse
	}
	if rawScope, present := fields["scope"]; present {
		var scope string
		if json.Unmarshal(rawScope, &scope) != nil || scope != readOnly {
			return p, ErrScopeMismatch
		}
	}
	// Scope omission is permitted by OAuth when it is identical to the
	// originally requested scope; every authorization request is read-only.
	return p, nil
}

// uniqueObject rejects duplicate keys, non-object roots and trailing data.
// Unknown future fields are bounded and ignored rather than leaked downstream.
func uniqueObject(body []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrInvalidResponse
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, ErrInvalidResponse
		}
		name, ok := key.(string)
		if !ok || fields[name] != nil {
			return nil, ErrInvalidResponse
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrInvalidResponse
		}
		fields[name] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') {
		return nil, ErrInvalidResponse
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalidResponse
	}
	return fields, nil
}
