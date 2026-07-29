// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamsdk

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// tokenEndpointSpy stands in for IAM and records the path the SDK actually
// POSTs the code exchange to, answering with a well-formed token so oauth2
// completes. Asserting the recorded path — not a string built in the test — is
// what makes this a wire test rather than a restatement of the code.
func tokenEndpointSpy(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","refresh_token":"ref","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// TestOAuthTokenEndpointMatchesDiscovery pins the code-exchange URL to the one
// the live IdP publishes in its OIDC discovery document:
//
//	token_endpoint = https://hanzo.id/v1/iam/oauth/token
//
// Every other spelling is served by something that is not the token endpoint —
// `/oauth/token` returns the SPA's index.html with 200, so the exchange fails
// with a JSON parse error rather than an auth error, and `/v1/iam/oauth/access_token`
// answers 401 (there is deliberately no legacy access_token alias). Both failure
// modes are silent at compile time, which is exactly why this is a test.
func TestOAuthTokenEndpointMatchesDiscovery(t *testing.T) {
	srv, got := tokenEndpointSpy(t)
	c := NewClient(srv.URL, "client-id", "client-secret", "", "hanzo", "hanzo-visor")

	if _, err := c.GetOAuthToken("the-code", "the-state"); err != nil {
		t.Fatalf("GetOAuthToken: %v", err)
	}
	if want := RoutePrefix + "/oauth/token"; *got != want {
		t.Errorf("code exchange POSTed to %q, want %q", *got, want)
	}
}

// TestRefreshOAuthTokenMatchesDiscovery pins the refresh grant to the SAME
// token endpoint (RFC 6749 §6 — refresh_token is a grant on token_endpoint, not
// a separate route). The lineage this SDK came from had a third spelling,
// /v1/iam/oauth/refresh_token, which the live IdP does not serve.
func TestRefreshOAuthTokenMatchesDiscovery(t *testing.T) {
	srv, got := tokenEndpointSpy(t)
	c := NewClient(srv.URL, "client-id", "client-secret", "", "hanzo", "hanzo-visor")

	if _, err := c.RefreshOAuthToken("the-refresh-token"); err != nil {
		t.Fatalf("RefreshOAuthToken: %v", err)
	}
	if want := RoutePrefix + "/oauth/token"; *got != want {
		t.Errorf("refresh POSTed to %q, want %q", *got, want)
	}
}

// TestOAuthAuthorizeURLMatchesDiscovery pins the browser-facing authorization
// URL to discovery's authorization_endpoint. It is never fetched by this SDK,
// so no spy can catch it — read it off the config the exchange is built from.
func TestOAuthAuthorizeURLMatchesDiscovery(t *testing.T) {
	c := NewClient("https://hanzo.id", "client-id", "client-secret", "", "hanzo", "hanzo-visor")

	if want := "https://hanzo.id" + RoutePrefix + "/oauth/authorize"; c.oauthConfig().Endpoint.AuthURL != want {
		t.Errorf("AuthURL = %q, want %q", c.oauthConfig().Endpoint.AuthURL, want)
	}
}
