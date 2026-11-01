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
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestDeviceAuthorizationResourceURI(t *testing.T) {
	for _, tc := range []struct {
		resource string
		valid    bool
	}{
		{"", true}, {"https://api.example.com/drive", true},
		{"https://api.example.com/drive?region=eu", true}, {"urn:example:drive", true},
		{"https://api.example.com/%23drive", true}, {"/drive", false},
		{"https://api.example.com/#drive", false}, {"https://api.example.com/#", false},
		{"https://api.example.com/%zz", false},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			if err := ValidateDeviceAuthResourceURI(tc.resource); (err == nil) != tc.valid {
				t.Fatalf("ValidateDeviceAuthResourceURI(%q) = %v, valid = %v", tc.resource, err, tc.valid)
			}
		})
	}
}

func TestDeviceAuthorizationMemory(t *testing.T) {
	testDeviceAuthorizationStore(t, &memoryDeviceAuthStore{})
}

// Set CASDOOR_TEST_REDIS_ADDR to run the same contract against a real Redis
// server. Only uniquely named device-auth keys are touched; no database is flushed.
func TestDeviceAuthorizationRedis(t *testing.T) {
	addr := os.Getenv("CASDOOR_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set CASDOOR_TEST_REDIS_ADDR to test the Redis backend")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	store := &redisDeviceAuthStore{client: client}
	testDeviceAuthorizationStore(t, store)
	t.Run("preserves TTL", func(t *testing.T) {
		key := "test-ttl-" + t.Name() + time.Now().Format("150405.000000000")
		cache := approvedDeviceAuthorization()
		store.Store(key, cache)
		t.Cleanup(func() { store.Delete(key) })
		ctx := context.Background()
		if err := client.PExpire(ctx, deviceAuthRedisPrefix+key, 15*time.Second).Err(); err != nil {
			t.Fatal(err)
		}
		before := client.PTTL(ctx, deviceAuthRedisPrefix+key).Val()
		value, ok := store.Load(key)
		if !ok {
			t.Fatal("missing grant")
		}
		cache = value.(DeviceAuthCache) // compare the Redis JSON round trip, as the endpoint does
		claimed := cache
		claimed.Status = DeviceAuthStatusTokenIssuing
		if !store.CompareAndSwap(key, cache, claimed) {
			t.Fatal("claim failed")
		}
		after := client.PTTL(ctx, deviceAuthRedisPrefix+key).Val()
		if after <= 0 || after > before || before-after > 2*time.Second {
			t.Fatalf("TTL changed unexpectedly: before %s, after %s", before, after)
		}
	})
	t.Run("connection failure", func(t *testing.T) {
		closed := redis.NewClient(&redis.Options{Addr: addr})
		_ = closed.Close()
		broken := &redisDeviceAuthStore{client: closed}
		cache := approvedDeviceAuthorization()
		claimed := cache
		claimed.Status = DeviceAuthStatusTokenIssuing
		if broken.CompareAndSwap("missing", cache, claimed) {
			t.Fatal("claimed through a failed Redis connection")
		}
	})
}

func approvedDeviceAuthorization() DeviceAuthCache {
	return DeviceAuthCache{
		UserSignIn: true, UserName: "organization/device-user", ApplicationId: "admin/device-app",
		ClientId: "device-client", Scope: "openid profile", Resource: "https://api.example.com/drive",
		RequestAt: time.Now(), Status: DeviceAuthStatusApproved, ExpiresIn: 120,
	}
}

func testDeviceAuthorizationStore(t *testing.T, store deviceAuthStore) {
	previous := DeviceAuthMap
	DeviceAuthMap = store
	t.Cleanup(func() { DeviceAuthMap = previous })
	newGrant := func(t *testing.T, cache DeviceAuthCache) string {
		key := "test-" + t.Name() + time.Now().Format("150405.000000000")
		store.Store(key, cache)
		t.Cleanup(func() { store.Delete(key) })
		return key
	}
	for _, tc := range []struct{ name, resource string }{{"inherited resource", ""}, {"repeated resource", "https://api.example.com/drive"}} {
		t.Run(tc.name, func(t *testing.T) {
			original := approvedDeviceAuthorization()
			key := newGrant(t, original)
			claimed, tokenErr := ClaimDeviceAuthorization(key, original.ClientId, tc.resource)
			if tokenErr != nil {
				t.Fatalf("claim failed: %+v", tokenErr)
			}
			if claimed.Resource != original.Resource || claimed.Scope != original.Scope || claimed.UserName != original.UserName || claimed.Status != DeviceAuthStatusTokenIssuing {
				t.Fatalf("grant binding changed: %+v", claimed)
			}
			if _, tokenErr = ClaimDeviceAuthorization(key, original.ClientId, tc.resource); tokenErr == nil {
				t.Fatal("code redeemed while minting")
			}
			issued := *claimed
			issued.Status = DeviceAuthStatusTokenIssued
			if !store.CompareAndSwap(key, *claimed, issued) {
				t.Fatal("could not complete issuance")
			}
			if _, tokenErr = ClaimDeviceAuthorization(key, original.ClientId, tc.resource); tokenErr == nil {
				t.Fatal("code redeemed after issuance")
			}
		})
	}
	t.Run("no resource", func(t *testing.T) {
		cache := approvedDeviceAuthorization()
		cache.Resource = ""
		key := newGrant(t, cache)
		if _, tokenErr := ClaimDeviceAuthorization(key, cache.ClientId, "https://api.example.com/new"); tokenErr == nil || tokenErr.Error != InvalidTarget {
			t.Fatalf("resource added to an unbound grant: %+v", tokenErr)
		}
		claimed, tokenErr := ClaimDeviceAuthorization(key, cache.ClientId, "")
		if tokenErr != nil || claimed.Resource != "" {
			t.Fatalf("unbound grant failed: %+v", tokenErr)
		}
	})
	t.Run("binding failures do not consume approval", func(t *testing.T) {
		cache := approvedDeviceAuthorization()
		key := newGrant(t, cache)
		if _, e := ClaimDeviceAuthorization(key, "another-client", cache.Resource); e == nil || e.Error != InvalidClient {
			t.Fatalf("client binding: %+v", e)
		}
		if _, e := ClaimDeviceAuthorization(key, cache.ClientId, "https://api.example.com/other"); e == nil || e.Error != InvalidTarget {
			t.Fatalf("resource binding: %+v", e)
		}
		if _, e := ClaimDeviceAuthorization(key, cache.ClientId, ""); e != nil {
			t.Fatalf("valid approval consumed by invalid request: %+v", e)
		}
	})
	for _, tc := range []struct {
		name, status string
		signedIn     bool
		age          time.Duration
		code         string
	}{
		{"pending", DeviceAuthStatusPending, false, 0, "authorization_pending"},
		{"signed in but pending", DeviceAuthStatusPending, true, 0, "authorization_pending"},
		{"approved but not signed in", DeviceAuthStatusApproved, false, 0, "authorization_pending"},
		{"denied", DeviceAuthStatusDenied, true, 0, "access_denied"},
		{"issuing", DeviceAuthStatusTokenIssuing, true, 0, "access_denied"},
		{"issued", DeviceAuthStatusTokenIssued, true, 0, "access_denied"},
		{"expired", DeviceAuthStatusApproved, true, -3 * time.Minute, "expired_token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := approvedDeviceAuthorization()
			cache.Status, cache.UserSignIn, cache.RequestAt = tc.status, tc.signedIn, time.Now().Add(tc.age)
			key := newGrant(t, cache)
			if _, e := ClaimDeviceAuthorization(key, cache.ClientId, ""); e == nil || e.Error != tc.code {
				t.Fatalf("got %+v, want %s", e, tc.code)
			}
		})
	}
	t.Run("concurrent redemption", func(t *testing.T) {
		cache := approvedDeviceAuthorization()
		key := newGrant(t, cache)
		var winners atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, e := ClaimDeviceAuthorization(key, cache.ClientId, ""); e == nil {
					winners.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("successful redemptions = %d, want 1", winners.Load())
		}
	})
	t.Run("stale snapshots and deleted grants", func(t *testing.T) {
		cache := approvedDeviceAuthorization()
		key := newGrant(t, cache)
		value, _ := store.Load(key)
		snapshot := value.(DeviceAuthCache)
		denied := snapshot
		denied.Status = DeviceAuthStatusDenied
		store.Store(key, denied)
		claimed := snapshot
		claimed.Status = DeviceAuthStatusTokenIssuing
		if store.CompareAndSwap(key, snapshot, claimed) {
			t.Fatal("claimed a changed grant")
		}
		store.Delete(key)
		if store.CompareAndSwap(key, snapshot, claimed) {
			t.Fatal("recreated a deleted grant")
		}
		if _, ok := store.Load(key); ok {
			t.Fatal("deleted grant was resurrected")
		}
		if _, e := ClaimDeviceAuthorization(key, cache.ClientId, ""); e == nil || e.Error != "expired_token" {
			t.Fatalf("missing grant: %+v", e)
		}
	})
}
