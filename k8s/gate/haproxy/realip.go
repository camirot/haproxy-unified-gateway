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
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/haproxytech/client-native/v6/models"
	v3 "github.com/haproxytech/haproxy-unified-gateway/api/gate/v3"
)

const (
	realIPTrustedPeerACL = "hug_trusted_peer"
	realIPHeaderFoundACL = "hug_realip_header_found"
)

var (
	realIPHeaderRegexp = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	realIPFileRegexp   = regexp.MustCompile(`^/\S+$`)
)

// validateRealIP checks a RealIPSpec before it is rendered in the configuration.
// The CRD already enforces the same constraints, this protects against a CRD
// installed from an older version and keeps untrusted strings out of the config.
func validateRealIP(spec *v3.RealIPSpec) error {
	if !realIPHeaderRegexp.MatchString(spec.Header) {
		return fmt.Errorf("invalid header %q", spec.Header)
	}
	hasFile := spec.TrustedPeersFile != ""
	hasCIDRs := len(spec.TrustedCIDRs) > 0
	if hasFile == hasCIDRs {
		return errors.New("exactly one of trustedPeersFile and trustedCIDRs must be set")
	}
	if hasFile && !realIPFileRegexp.MatchString(spec.TrustedPeersFile) {
		return fmt.Errorf("invalid trustedPeersFile %q", spec.TrustedPeersFile)
	}
	for _, c := range spec.TrustedCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			if _, errAddr := netip.ParseAddr(c); errAddr != nil {
				return fmt.Errorf("invalid trusted CIDR %q", c)
			}
		}
	}
	switch spec.Mode {
	case "", v3.RealIPModeSetSrc, v3.RealIPModeLogOnly:
	default:
		return fmt.Errorf("invalid mode %q", spec.Mode)
	}
	return nil
}

// realIPRules returns the ACLs and http-request rules that take the client
// address from a request header, only when the TCP peer is a trusted proxy:
//
//	acl hug_trusted_peer src -f <file>            (or: src <cidr> <cidr> ...)
//	acl hug_realip_header_found req.hdr(<h>) -m found
//	http-request set-src req.hdr(<h>) if hug_trusted_peer hug_realip_header_found
//	(logOnly: http-request set-var(txn.realip) req.hdr(<h>) if hug_trusted_peer hug_realip_header_found)
//
// Both conditions are required: without the trusted-peer test any visitor could
// spoof its address. The rules must run before anything else in the frontend.
func realIPRules(spec *v3.RealIPSpec) ([]*models.HTTPRequestRule, []*models.ACL) {
	value := "-f " + spec.TrustedPeersFile
	if spec.TrustedPeersFile == "" {
		value = strings.Join(spec.TrustedCIDRs, " ")
	}
	expr := "req.hdr(" + spec.Header + ")"
	acls := []*models.ACL{
		{
			ACLName:   realIPTrustedPeerACL,
			Criterion: "src",
			Value:     value,
			Metadata:  map[string]any{"hug": "realIP: TCP peer is a trusted proxy"},
		},
		{
			ACLName:   realIPHeaderFoundACL,
			Criterion: expr,
			Value:     "-m found",
			Metadata:  map[string]any{"hug": "realIP: client address header present"},
		},
	}
	rule := &models.HTTPRequestRule{
		Cond:     "if",
		CondTest: realIPTrustedPeerACL + " " + realIPHeaderFoundACL,
	}
	if spec.Mode == v3.RealIPModeLogOnly {
		rule.Type = "set-var"
		rule.VarName = "realip"
		rule.VarScope = "txn"
		rule.VarExpr = expr
		rule.Metadata = map[string]any{"hug": "realIP: store client address in txn.realip"}
	} else {
		rule.Type = "set-src"
		rule.Expr = expr
		rule.Metadata = map[string]any{"hug": "realIP: set source address from header"}
	}
	return []*models.HTTPRequestRule{rule}, acls
}
