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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haproxytech/client-native/v6/configuration"
	cfgoptions "github.com/haproxytech/client-native/v6/configuration/options"
	"github.com/haproxytech/client-native/v6/models"
	v3 "github.com/haproxytech/haproxy-unified-gateway/api/gate/v3"
)

// TestRealIPRenderedConfig renders the realIP rules through client-native
// (HAProxy itself is stubbed, so the output is not validated by HAProxy) and checks the resulting configuration text.
func TestRealIPRenderedConfig(t *testing.T) {
	tests := []struct {
		name string
		spec *v3.RealIPSpec
		want []string
	}{
		{
			name: "set-src with file",
			spec: &v3.RealIPSpec{Header: "CF-Connecting-IP", TrustedPeersFile: "/usr/local/hug/aux/cloudflare-ips.lst"},
			want: []string{
				"acl hug_trusted_peer src -f /usr/local/hug/aux/cloudflare-ips.lst",
				"acl hug_realip_header_found req.hdr(CF-Connecting-IP) -m found",
				"http-request set-src req.hdr(CF-Connecting-IP) if hug_trusted_peer hug_realip_header_found",
			},
		},
		{
			name: "logOnly with inline CIDRs",
			spec: &v3.RealIPSpec{
				Header: "CF-Connecting-IP", TrustedCIDRs: []string{"173.245.48.0/20", "2400:cb00::/32"},
				Mode: v3.RealIPModeLogOnly,
			},
			want: []string{
				"acl hug_trusted_peer src 173.245.48.0/20 2400:cb00::/32",
				"http-request set-var(txn.realip) req.hdr(CF-Connecting-IP) if hug_trusted_peer hug_realip_header_found",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgFile := filepath.Join(dir, "haproxy.cfg")
			if err := os.WriteFile(cfgFile, []byte("global\n\ndefaults\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// the commit validates the file with "haproxy -c": use a stub that accepts everything
			stub := filepath.Join(dir, "haproxy")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec
				t.Fatal(err)
			}
			client, err := configuration.New(context.Background(),
				cfgoptions.ConfigurationFile(cfgFile),
				cfgoptions.TransactionsDir(filepath.Join(dir, "transactions")),
				cfgoptions.UseModelsValidation,
				cfgoptions.HAProxyBin(stub),
			)
			if err != nil {
				t.Fatal(err)
			}
			rules, acls := realIPRules(tt.spec)
			fe := models.Frontend{
				FrontendBase:        models.FrontendBase{Name: "fe", Mode: "http"},
				ACLList:             acls,
				HTTPRequestRuleList: rules,
			}
			version, err := client.GetVersion("")
			if err != nil {
				t.Fatal(err)
			}
			tr, err := client.StartTransaction(version)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.CreateStructuredFrontend(&fe, tr.ID, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CommitTransaction(tr.ID); err != nil {
				t.Fatal(err)
			}
			out, err := os.ReadFile(cfgFile)
			if err != nil {
				t.Fatal(err)
			}
			rendered := strings.Join(strings.Fields(string(out)), " ")
			for _, w := range tt.want {
				if !strings.Contains(rendered, strings.Join(strings.Fields(w), " ")) {
					t.Errorf("missing %q in rendered config:\n%s", w, out)
				}
			}
		})
	}
}
