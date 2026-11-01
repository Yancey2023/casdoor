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

package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func deviceTestController(t *testing.T, path string, values url.Values) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(recorder, request)
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", nil)
	return controller, recorder
}

func assertDeviceHTTPError(t *testing.T, recorder *httptest.ResponseRecorder, code string) {
	t.Helper()
	var response object.TokenError
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadRequest || response.Error != code {
		t.Fatalf("status=%d error=%q, want status=400 error=%q", recorder.Code, response.Error, code)
	}
}

// Invalid resource requests must fail at the HTTP boundary before looking up
// an application or creating any device authorization state.
func TestDeviceAuthorizationHTTPInvalidResource(t *testing.T) {
	for _, resource := range []string{"relative/path", "https://api.example.com/#", "https://api.example.com/#fragment"} {
		t.Run(resource, func(t *testing.T) {
			controller, recorder := deviceTestController(t, "/api/device-auth", url.Values{"client_id": {"device-client"}, "resource": {resource}})
			controller.DeviceAuth()
			assertDeviceHTTPError(t, recorder, object.InvalidTarget)
		})
	}
}

func TestDeviceAuthorizationHTTPGrantType(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values url.Values
	}{
		{"missing device code", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"device-client"}}},
		{"device code with another grant", url.Values{"grant_type": {"password"}, "device_code": {"unused-code"}, "client_id": {"device-client"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, recorder := deviceTestController(t, "/api/login/oauth/access_token", tc.values)
			controller.GetOAuthToken()
			assertDeviceHTTPError(t, recorder, object.InvalidRequest)
		})
	}
}
