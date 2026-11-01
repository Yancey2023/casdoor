// Copyright 2026 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"path/filepath"
	"testing"
)

// Exercise the real SQL persistence and JWT signing/verification paths without
// depending on an existing Casdoor database, remote identity provider or account.
func TestDeviceAuthorizationTokenResource(t *testing.T) {
	previous := ormer
	adapter, err := NewAdapter("sqlite", filepath.Join(t.TempDir(), "device-auth.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	ormer = adapter
	t.Cleanup(func() { ormer = previous; _ = adapter.Engine.Close() })
	if err = adapter.Engine.Sync2(new(User), new(Role), new(Permission), new(Cert), new(Token)); err != nil {
		t.Fatal(err)
	}
	certificate, privateKey, err := generateRsaKeys(2048, 256, 1, "Device test", "Device test")
	if err != nil {
		t.Fatal(err)
	}
	cert := &Cert{Owner: "device-org", Name: "device-cert", Certificate: certificate, PrivateKey: privateKey}
	user := &User{Owner: "device-org", Name: "device-user", Id: "device-user-id", Type: "normal-user"}
	if _, err = adapter.Engine.Insert(cert, user); err != nil {
		t.Fatal(err)
	}
	application := &Application{
		Owner: "admin", Name: "device-app", Organization: user.Owner,
		ClientId: "device-client", Cert: cert.Name, TokenFormat: "JWT", ExpireInHours: 1, RefreshExpireInHours: 2,
	}
	for _, resource := range []string{"https://api.example.com/drive", ""} {
		t.Run(resource, func(t *testing.T) {
			token, tokenErr, err := GetDeviceCodeToken(application, user.GetId(), "openid profile", "device-nonce", resource, "localhost:8000")
			if err != nil || tokenErr != nil {
				t.Fatalf("mint: %v, %+v", err, tokenErr)
			}
			stored, err := GetTokenByRefreshToken(token.RefreshToken)
			if err != nil || stored == nil {
				t.Fatalf("persisted grant: %v", err)
			}
			if stored.Resource != resource {
				t.Fatalf("stored resource = %q, want %q", stored.Resource, resource)
			}
			assertDeviceTokenAudience(t, token.AccessToken, cert, resource, application.ClientId, "access-token")
			assertDeviceTokenAudience(t, token.IdToken, cert, "", application.ClientId, "id-token")
			refreshed, err := RefreshToken(application, "refresh_token", token.RefreshToken, "", application.ClientId, "", "", "localhost:8000", "", "")
			if err != nil {
				t.Fatal(err)
			}
			wrapper, ok := refreshed.(*TokenWrapper)
			if !ok {
				t.Fatalf("refresh: %+v", refreshed)
			}
			assertDeviceTokenAudience(t, wrapper.AccessToken, cert, resource, application.ClientId, "access-token")
			assertDeviceTokenAudience(t, wrapper.IdToken, cert, "", application.ClientId, "id-token")
			refreshedGrant, err := GetTokenByRefreshToken(wrapper.RefreshToken)
			if err != nil || refreshedGrant == nil || refreshedGrant.Resource != resource {
				t.Fatalf("refreshed grant lost resource: %+v, %v", refreshedGrant, err)
			}
			rejected, err := RefreshToken(application, "refresh_token", wrapper.RefreshToken, "", application.ClientId, "", "https://api.example.com/other", "localhost:8000", "", "")
			rejection, ok := rejected.(*TokenError)
			if err != nil || !ok || rejection.Error != InvalidGrant {
				t.Fatalf("refresh changed resource: %+v, %v", rejected, err)
			}
		})
	}
}

func assertDeviceTokenAudience(t *testing.T, raw string, cert *Cert, resource, clientId, tokenType string) {
	t.Helper()
	claims, err := ParseJwtToken(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	want := resource
	if want == "" {
		want = clientId
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != want || claims.Azp != clientId || claims.TokenType != tokenType {
		t.Fatalf("unexpected claims: audience=%v azp=%q tokenType=%q, want audience=%q azp=%q tokenType=%q", claims.Audience, claims.Azp, claims.TokenType, want, clientId, tokenType)
	}
}
