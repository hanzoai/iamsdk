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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder is an HttpClient that answers every request with an empty, well-formed
// IAM envelope and remembers the URL it was asked for. No network, no server.
type recorder struct{ url *url.URL }

func (r *recorder) Do(req *http.Request) (*http.Response, error) {
	r.url = req.URL
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"status":"ok","data":[],"data2":0}`)),
		Header:     http.Header{},
	}, nil
}

// withRecorder swaps the package http client for the duration of one test.
func withRecorder(t *testing.T) *recorder {
	t.Helper()
	prev := client
	r := &recorder{}
	client = r
	t.Cleanup(func() { client = prev })
	return r
}

func testClient() *Client {
	return NewClient("https://iam.hanzo.ai", "id", "secret", "", "hanzo", "hanzo-console")
}

// TestPaginationHonoursExplicitOwner is the whole point. A caller that names an
// org gets that org on the wire. Whether it may READ that org is the server's
// call — authz.Scope honours it or refuses it — and a refusal is an answer the
// caller can see. Rewriting owner here would make the question unaskable.
func TestPaginationHonoursExplicitOwner(t *testing.T) {
	r := withRecorder(t)
	c := testClient()

	if _, _, err := c.GetPaginationUsers(1, 10, map[string]string{"owner": "lux"}); err != nil {
		t.Fatalf("GetPaginationUsers: %v", err)
	}
	if got := r.url.Query().Get("owner"); got != "lux" {
		t.Fatalf("owner on the wire = %q, want %q (the client silently rewrote the caller's org)", got, "lux")
	}
}

// TestPaginationDefaultsToConfiguredOrg pins the other half: with no owner
// stated, the client's configured org is the default. A default is not an
// override.
func TestPaginationDefaultsToConfiguredOrg(t *testing.T) {
	r := withRecorder(t)
	c := testClient()

	if _, _, err := c.GetPaginationUsers(1, 10, map[string]string{}); err != nil {
		t.Fatalf("GetPaginationUsers: %v", err)
	}
	if got := r.url.Query().Get("owner"); got != "hanzo" {
		t.Fatalf("owner on the wire = %q, want %q", got, "hanzo")
	}
	if got := r.url.Query().Get("pageSize"); got != "10" {
		t.Fatalf("pageSize = %q, want %q", got, "10")
	}
}

// TestPaginationTokensDefaultToAdmin keeps the one list route whose default is
// not the configured org: tokens are owned by "admin".
func TestPaginationTokensDefaultToAdmin(t *testing.T) {
	r := withRecorder(t)
	c := testClient()

	if _, _, err := c.GetPaginationTokens(1, 10, map[string]string{}); err != nil {
		t.Fatalf("GetPaginationTokens: %v", err)
	}
	if got := r.url.Query().Get("owner"); got != "admin" {
		t.Fatalf("owner on the wire = %q, want %q", got, "admin")
	}
}

// TestPaginationDoesNotMutateCallersMap: a query is a value. The caller keeps
// exactly what it passed in — no owner rewritten under it, no page coordinates
// smuggled into a map it may reuse for the next call.
func TestPaginationDoesNotMutateCallersMap(t *testing.T) {
	withRecorder(t)
	c := testClient()

	q := map[string]string{"owner": "lux"}
	if _, _, err := c.GetPaginationUsers(2, 25, q); err != nil {
		t.Fatalf("GetPaginationUsers: %v", err)
	}
	if len(q) != 1 || q["owner"] != "lux" {
		t.Fatalf("caller's map was mutated: %v, want map[owner:lux]", q)
	}
}

// TestNoRouteWritesToCallersQuery is the regression guard, and it states the
// invariant rather than a spelling: a `queryMap map[string]string` PARAMETER is
// the caller's value, and no function may assign into it. Renaming the variable
// does not evade this — the check is anchored on the parameter, found through
// go/ast, so the compiler's own notion of "this identifier is that parameter" is
// what decides.
//
// The one place page coordinates and the owner default are applied is page() in
// util.go, which copies first.
func TestNoRouteWritesToCallersQuery(t *testing.T) {
	self := "scope_test.go"

	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules"):
			return filepath.SkipDir
		case d.IsDir(), filepath.Ext(path) != ".go", d.Name() == self:
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Type.Params == nil {
				continue
			}
			params := map[string]bool{}
			for _, field := range fn.Type.Params.List {
				mt, ok := field.Type.(*ast.MapType)
				if !ok {
					continue
				}
				if k, ok := mt.Key.(*ast.Ident); !ok || k.Name != "string" {
					continue
				}
				for _, name := range field.Names {
					params[name.Name] = true
				}
			}
			if len(params) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					ix, ok := lhs.(*ast.IndexExpr)
					if !ok {
						continue
					}
					if id, ok := ix.X.(*ast.Ident); ok && params[id.Name] {
						offenders = append(offenders,
							fset.Position(as.Pos()).String()+": "+fn.Name.Name+" writes into its caller's "+id.Name)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("a caller-supplied query map is a value, not scratch space; found %d write(s):\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}
