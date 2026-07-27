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
	"go/ast"
	"go/parser"
	"go/token"
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

// bannedPrefix matches an `/api/` PATH segment. It deliberately does NOT match
// the `api.hanzo.ai` HOSTNAME — the standard bans the path segment, not the
// api.* subdomain.
var bannedPrefix = regexp.MustCompile(`(^|[^.\w])/api/`)

// TestNoApiPrefixInRouteLiterals is the regression guard: every action this SDK
// calls is a verb-noun under RoutePrefix, and no string literal in the module
// may address IAM any other way.
//
// It inspects STRING LITERALS via go/ast, not lines of text: only a literal can
// BE a route. Prose that names the prefix — a comment explaining what this
// replaced — is documentation, and the parser tells the two apart exactly.
func TestNoApiPrefixInRouteLiterals(t *testing.T) {
	self := "route_prefix_test.go" // names the banned prefix in order to ban it

	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules"):
			return filepath.SkipDir
		case d.IsDir(), filepath.Ext(path) != ".go", d.Name() == self:
			return nil
		}
		// ParseFile without ParseComments: comments are prose, not routes.
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, uerr := strconv.Unquote(lit.Value); uerr == nil && bannedPrefix.MatchString(v) {
				offenders = append(offenders, fset.Position(lit.Pos()).String()+": "+lit.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("the /api/ prefix is banned (use RoutePrefix = %q); found %d banned route literal(s):\n%s",
			RoutePrefix, len(offenders), strings.Join(offenders, "\n"))
	}
}
