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
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

// live points the package's global client at a REAL IAM and returns the
// organization and application the caller should own its rows under. When no
// server is configured it skips the test instead.
//
// Every integration test in this package drives a live server — it creates,
// reads, updates and deletes rows. "Is there a server to talk to?" is therefore
// ONE question, and this is the one place that answers it.
//
// It used to be answered 31 times over, by 31 copies of the same InitConfig
// call against a hard-coded vendor demo host that does not resolve. So all 31
// failed on every run, permanently, and a gate that cannot go green gets
// parked: this repo's workflow still triggered on `master`, a branch it stopped
// pushing to when the default became `main`. The result is that v2.2.2 — the
// commit that stopped this client from silently rewriting a caller's `owner`,
// i.e. a cross-tenant scoping fix — shipped with no test run at all.
//
// The credential comes from the environment because a credential belongs in
// KMS, never in a source file. The values it replaces lived in test_util.go,
// which had no _test suffix, so the secret was compiled into every binary that
// linked this SDK. IAM_TEST_CERT is optional: only ParseJwtToken reads it.
func live(t *testing.T) (org, app string) {
	t.Helper()
	endpoint, id, secret := os.Getenv("IAM_TEST_ENDPOINT"), os.Getenv("IAM_TEST_CLIENT_ID"), os.Getenv("IAM_TEST_CLIENT_SECRET")
	org, app = os.Getenv("IAM_TEST_ORGANIZATION"), os.Getenv("IAM_TEST_APPLICATION")
	if endpoint == "" || id == "" || secret == "" || org == "" || app == "" {
		t.Skip("no live IAM: set IAM_TEST_ENDPOINT, IAM_TEST_CLIENT_ID, IAM_TEST_CLIENT_SECRET, IAM_TEST_ORGANIZATION, IAM_TEST_APPLICATION")
	}
	InitConfig(endpoint, id, secret, os.Getenv("IAM_TEST_CERT"), org, app)
	return org, app
}

func getRandomCode(length int) string {
	var stdNums = []byte("0123456789")
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, stdNums[r.Intn(len(stdNums))])
	}
	return string(result)
}

func getRandomName(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, getRandomCode(6))
}
