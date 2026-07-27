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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestGetUrlUsesV1IamPrefix(t *testing.T) {
	c := &Client{AuthConfig: AuthConfig{Endpoint: "https://iam.hanzo.ai"}}

	got := c.GetUrl("get-users", map[string]string{"owner": "hanzo"})
	want := "https://iam.hanzo.ai/v1/iam/get-users?owner=hanzo"
	if got != want {
		t.Fatalf("GetUrl = %q, want %q", got, want)
	}
}

// apiPrefix matches an `/api/` PATH segment. It deliberately does NOT match the
// `api.hanzo.ai` HOSTNAME — the standard bans the path segment, not the api.*
// subdomain.
var apiPrefix = regexp.MustCompile(`(^|[^.\w])/api/`)

// TestNoApiPrefixInSource is the regression guard: it fails if any Go source in
// this module reintroduces an `/api/` route segment. The prefix has exactly one
// spelling — RoutePrefix — and this test is what keeps it that way.
func TestNoApiPrefixInSource(t *testing.T) {
	self := "route_prefix_test.go" // names the banned prefix in order to ban it

	var offenders []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules"):
			return filepath.SkipDir
		case d.IsDir(), filepath.Ext(path) != ".go", d.Name() == self:
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if apiPrefix.MatchString(line) {
				offenders = append(offenders, path+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("the /api/ prefix is banned (use RoutePrefix = %q); found %d occurrence(s):\n%s",
			RoutePrefix, len(offenders), strings.Join(offenders, "\n"))
	}
}
