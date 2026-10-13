package credentials

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"
)

var testExpiry = time.Date(2026, 10, 13, 20, 0, 0, 123, time.UTC)

const testAccess = "synthetic-access-sensitive-marker"
const testRefresh = "synthetic-refresh-sensitive-marker"

func bundle(t *testing.T) CompleteBundle {
	t.Helper()
	b, err := NewOAuthBundle(testAccess, testRefresh, testExpiry, ReadOnlyScope)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func assertNoSecrets(t *testing.T, s string) {
	t.Helper()
	for _, secret := range []string{testAccess, testRefresh} {
		if strings.Contains(s, secret) {
			t.Fatal("secret marker leaked")
		}
	}
}
func TestCompleteBundleRedactsAllGenericSerializationAndLogging(t *testing.T) {
	b := bundle(t)
	for _, v := range []any{b, &b, []CompleteBundle{b}, []any{&b}, map[string]any{"credential": b}, struct{ Value CompleteBundle }{b}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
			assertNoSecrets(t, fmt.Sprintf(format, v))
		}
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, xml.Marshal} {
			encoded, _ := marshal(v)
			assertNoSecrets(t, string(encoded))
		}
		var output bytes.Buffer
		log.New(&output, "", 0).Printf("%#v", v)
		slog.New(slog.NewJSONHandler(&output, nil)).Info("synthetic", "value", v)
		slog.New(slog.NewTextHandler(&output, nil)).Info("synthetic", "value", v)
		assertNoSecrets(t, output.String())
	}
	raw, err := json.Marshal(b)
	if err != nil || string(raw) != `"[redacted YNAB credentials]"` {
		t.Fatal("JSON must be explicitly redacted")
	}
	if err := json.Unmarshal([]byte(`{"access_token":"`+testAccess+`"}`), &b); !errors.Is(err, ErrInvalidBundle) {
		t.Fatal("generic unmarshal accepted credential input")
	}
	if !b.Equal(bundle(t)) {
		t.Fatal("generic unmarshal changed existing credentials")
	}
}
func TestCompleteBundleRejectsMissingInvalidOrOversizedFields(t *testing.T) {
	cases := []struct {
		access, refresh string
		expiry          time.Time
		scope           string
	}{
		{"", testRefresh, testExpiry, ReadOnlyScope}, {testAccess, "", testExpiry, ReadOnlyScope},
		{testAccess, testRefresh, time.Time{}, ReadOnlyScope}, {testAccess, testRefresh, time.Unix(0, 0), ReadOnlyScope},
		{testAccess, testRefresh, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), ReadOnlyScope},
		{testAccess, testRefresh, testExpiry, ""}, {testAccess, testRefresh, testExpiry, "read-only write"},
		{"with space", testRefresh, testExpiry, ReadOnlyScope}, {testAccess, "newline\n", testExpiry, ReadOnlyScope},
		{"nonascii-\xff", testRefresh, testExpiry, ReadOnlyScope}, {testAccess, "nul\x00", testExpiry, ReadOnlyScope},
		{strings.Repeat("a", MaxTokenBytes+1), testRefresh, testExpiry, ReadOnlyScope},
		{testAccess, strings.Repeat("r", MaxTokenBytes+1), testExpiry, ReadOnlyScope},
	}
	for i, c := range cases {
		got, err := NewOAuthBundle(c.access, c.refresh, c.expiry, c.scope)
		if !errors.Is(err, ErrInvalidBundle) || got.Validate() == nil {
			t.Fatalf("invalid case %d accepted", i)
		}
		assertNoSecrets(t, fmt.Sprint(err))
	}
	if (CompleteBundle{}).Validate() == nil || (CompleteBundle{}).Equal(CompleteBundle{}) {
		t.Fatal("zero bundle is valid")
	}
}
func TestProtectedSerializationRoundTripsExactCompleteBundle(t *testing.T) {
	b := bundle(t)
	raw, err := b.MarshalForProtectedStore()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(testAccess)) || !bytes.Contains(raw, []byte(testRefresh)) {
		t.Fatal("explicit store export lacks complete pair")
	}
	restored, err := UnmarshalFromProtectedStore(raw)
	if err != nil || !restored.Equal(b) {
		t.Fatal("exact complete-bundle roundtrip failed")
	}
	if !restored.ReadOnly() || !restored.ExpiresAt().Equal(testExpiry) || restored.ExportAccessTokenForYNABRead() != testAccess || restored.ExportRefreshTokenForOAuth() != testRefresh {
		t.Fatal("validated fields changed")
	}
	for _, change := range []CompleteBundle{
		{accessToken: testAccess + "x", refreshToken: testRefresh, expiresAt: testExpiry, scope: ReadOnlyScope},
		{accessToken: testAccess, refreshToken: testRefresh + "x", expiresAt: testExpiry, scope: ReadOnlyScope},
		{accessToken: testAccess, refreshToken: testRefresh, expiresAt: testExpiry.Add(time.Nanosecond), scope: ReadOnlyScope},
		{accessToken: testAccess, refreshToken: testRefresh, expiresAt: testExpiry, scope: "write"},
	} {
		if restored.Equal(change) {
			t.Fatal("comparison missed a credential field")
		}
	}
	// Quotes/backslashes are safe, with no expansion beyond the explicit bound.
	max, err := NewOAuthBundle(strings.Repeat("\"", MaxTokenBytes), strings.Repeat("\\", MaxTokenBytes), testExpiry, ReadOnlyScope)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = max.MarshalForProtectedStore()
	if err != nil || len(raw) > MaxPlaintextBytes {
		t.Fatal("bounded valid credentials rejected")
	}
	got, err := UnmarshalFromProtectedStore(raw)
	if err != nil || !got.Equal(max) {
		t.Fatal("escaped maximum credentials changed")
	}
}
func TestProtectedSerializationRejectsMalformedAmbiguousAndIncompleteRecords(t *testing.T) {
	b := bundle(t)
	raw, _ := b.MarshalForProtectedStore()
	cases := [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(`[]`), bytes.Repeat([]byte{'x'}, MaxPlaintextBytes+1), append(bytes.Clone(raw), []byte(` {}`)...), append([]byte{' '}, raw...)}
	for _, pair := range [][2]string{
		{`"version":1`, `"version":2`}, {`"version":1`, `"version":1,"version":1`},
		{`"scope":"read-only"`, `"scope":"write"`}, {`"scope":"read-only"`, `"scope":""`},
		{`"scope":"read-only"`, `"scope":"read-only","extra":"x"`},
		{`"refresh_token":"` + testRefresh + `"`, `"refresh_token":""`},
		{`"access_token":"` + testAccess + `"`, `"access_token":null`},
		{testExpiry.Format(time.RFC3339Nano), "bad-time"},
	} {
		cases = append(cases, []byte(strings.Replace(string(raw), pair[0], pair[1], 1)))
	}
	for i, raw := range cases {
		got, err := UnmarshalFromProtectedStore(raw)
		if !errors.Is(err, ErrInvalidBundle) || got.Validate() == nil {
			t.Fatalf("invalid encoding case %d accepted", i)
		}
		assertNoSecrets(t, fmt.Sprint(err))
	}
}
func FuzzProtectedBundleDecode(f *testing.F) {
	b, _ := NewOAuthBundle(testAccess, testRefresh, testExpiry, ReadOnlyScope)
	raw, _ := b.MarshalForProtectedStore()
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := UnmarshalFromProtectedStore(raw)
		if err != nil {
			return
		}
		if b.Validate() != nil {
			t.Fatal("accepted invalid bundle")
		}
		canonical, err := b.MarshalForProtectedStore()
		if err != nil || !bytes.Equal(canonical, raw) {
			t.Fatal("accepted noncanonical bundle")
		}
		assertNoSecrets(t, fmt.Sprintf("%#v", b))
	})
}
