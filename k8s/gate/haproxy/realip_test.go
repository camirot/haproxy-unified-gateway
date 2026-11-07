// Copyright 2025 HAProxy Technologies LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package haproxy

import (
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/haproxytech/client-native/v6/models"
	v3 "github.com/haproxytech/haproxy-unified-gateway/api/gate/v3"
	"github.com/haproxytech/haproxy-unified-gateway/k8s/gate/tree"
)

func realIPHTTPRules(realIP *v3.RealIPSpec) ([]*models.HTTPRequestRule, []*models.ACL) {
	return httpFrontendRules(realIP,
		"/maps/fe/listener_exact_match.map",
		"/maps/fe/listener_wildcard_match.map",
		"/maps/fe/listener_route_exact_match.map",
		"/maps/fe/listener_route_wildcard_match.map",
		"/maps/fe/path_exact.map",
		"/maps/fe/path_prefix.map",
		"/maps/fe/path_regex.map",
		"/maps/fe",
	)
}

func TestHTTPFrontendRulesRealIPSetSrc(t *testing.T) {
	spec := &v3.RealIPSpec{Header: "CF-Connecting-IP", TrustedPeersFile: "/usr/local/hug/aux/cloudflare-ips.lst"}
	baseRules, baseACLs := realIPHTTPRules(nil)
	rules, acls := realIPHTTPRules(spec)

	// the rewrite comes first, everything else is untouched
	if len(rules) != len(baseRules)+1 {
		t.Fatalf("got %d rules, want %d", len(rules), len(baseRules)+1)
	}
	r := rules[0]
	if r.Type != "set-src" || r.Expr != "req.hdr(CF-Connecting-IP)" || r.Cond != "if" ||
		r.CondTest != "hug_trusted_peer hug_realip_header_found" {
		t.Errorf("unexpected first rule: %+v", r)
	}
	if !reflect.DeepEqual(rules[1:], baseRules) {
		t.Error("existing rules changed")
	}
	if !reflect.DeepEqual(acls[2:], baseACLs) {
		t.Error("existing ACLs changed")
	}
	if acls[0].ACLName != "hug_trusted_peer" || acls[0].Criterion != "src" ||
		acls[0].Value != "-f /usr/local/hug/aux/cloudflare-ips.lst" {
		t.Errorf("unexpected trusted peer ACL: %+v", acls[0])
	}
	if acls[1].ACLName != "hug_realip_header_found" || acls[1].Criterion != "req.hdr(CF-Connecting-IP)" ||
		acls[1].Value != "-m found" {
		t.Errorf("unexpected header ACL: %+v", acls[1])
	}
}

func TestHTTPFrontendRulesRealIPLogOnlyInlineCIDRs(t *testing.T) {
	spec := &v3.RealIPSpec{
		Header:       "X-Real",
		TrustedCIDRs: []string{"173.245.48.0/20", "2400:cb00::/32"},
		Mode:         v3.RealIPModeLogOnly,
	}
	rules, acls := realIPHTTPRules(spec)
	r := rules[0]
	if r.Type != "set-var" || r.VarScope != "txn" || r.VarName != "realip" || r.VarExpr != "req.hdr(X-Real)" ||
		r.CondTest != "hug_trusted_peer hug_realip_header_found" {
		t.Errorf("unexpected first rule: %+v", r)
	}
	if acls[0].Value != "173.245.48.0/20 2400:cb00::/32" {
		t.Errorf("unexpected trusted peer ACL value %q", acls[0].Value)
	}
}

// With realIP unset nothing related to it may be rendered.
func TestHTTPFrontendRulesRealIPUnset(t *testing.T) {
	rules, acls := realIPHTTPRules(nil)
	for _, r := range rules {
		if r.Type == "set-src" || strings.Contains(r.CondTest, "hug_trusted_peer") || r.VarName == "realip" {
			t.Errorf("unexpected realIP rule: %+v", r)
		}
	}
	for _, a := range acls {
		if strings.HasPrefix(a.ACLName, "hug_trusted_peer") || strings.HasPrefix(a.ACLName, "hug_realip") {
			t.Errorf("unexpected realIP ACL: %+v", a)
		}
	}
}

// TCP / TLS passthrough frontends never get the rules.
func TestTLSPassthroughRulesNoRealIP(t *testing.T) {
	tcpRules, _, acls := tlsPassthroughRules("/a", "/b", "/c", "/d", "/e")
	for _, r := range tcpRules {
		if strings.Contains(r.CondTest, "hug_trusted_peer") {
			t.Errorf("unexpected realIP rule: %+v", r)
		}
	}
	for _, a := range acls {
		if strings.HasPrefix(a.ACLName, "hug_") {
			t.Errorf("unexpected realIP ACL: %+v", a)
		}
	}
}

func TestValidateRealIP(t *testing.T) {
	tests := []struct {
		name    string
		spec    v3.RealIPSpec
		wantErr bool
	}{
		{name: "file", spec: v3.RealIPSpec{Header: "CF-Connecting-IP", TrustedPeersFile: "/x/y.lst"}},
		{name: "cidrs", spec: v3.RealIPSpec{Header: "H", TrustedCIDRs: []string{"10.0.0.0/8", "::1", "fd00::/8"}}},
		{name: "log only", spec: v3.RealIPSpec{Header: "H", TrustedCIDRs: []string{"10.0.0.0/8"}, Mode: v3.RealIPModeLogOnly}},
		{name: "no peers", spec: v3.RealIPSpec{Header: "H"}, wantErr: true},
		{name: "both peers", spec: v3.RealIPSpec{Header: "H", TrustedPeersFile: "/x", TrustedCIDRs: []string{"10.0.0.0/8"}}, wantErr: true},
		{name: "header with space", spec: v3.RealIPSpec{Header: "H x", TrustedPeersFile: "/x"}, wantErr: true},
		{name: "empty header", spec: v3.RealIPSpec{TrustedPeersFile: "/x"}, wantErr: true},
		{name: "relative file", spec: v3.RealIPSpec{Header: "H", TrustedPeersFile: "x"}, wantErr: true},
		{name: "file with space", spec: v3.RealIPSpec{Header: "H", TrustedPeersFile: "/x y"}, wantErr: true},
		{name: "bad cidr", spec: v3.RealIPSpec{Header: "H", TrustedCIDRs: []string{"10.0.0.0/8 any"}}, wantErr: true},
		{name: "bad mode", spec: v3.RealIPSpec{Header: "H", TrustedPeersFile: "/x", Mode: "nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRealIP(&tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRealIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// An invalid spec must fail closed: no rule is generated, so the client
// address is never taken from a header.
func TestRealIPForFrontend(t *testing.T) {
	newMgr := func(spec *v3.RealIPSpec) *HaproxyConfMgrImpl {
		gt := tree.NewGateTree()
		gt.RealIP = spec
		return &HaproxyConfMgrImpl{
			logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
			controllerStore: &tree.ControllerStore{GateTree: gt},
		}
	}
	if got := newMgr(nil).realIPForFrontend("fe"); got != nil {
		t.Errorf("got %+v for unset realIP", got)
	}
	if got := newMgr(&v3.RealIPSpec{Header: "H"}).realIPForFrontend("fe"); got != nil {
		t.Errorf("got %+v for invalid realIP", got)
	}
	valid := &v3.RealIPSpec{Header: "H", TrustedPeersFile: "/x"}
	if got := newMgr(valid).realIPForFrontend("fe"); got != valid {
		t.Errorf("got %+v for valid realIP", got)
	}
}
