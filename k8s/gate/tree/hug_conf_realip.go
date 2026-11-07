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
package tree

import (
	v3 "github.com/haproxytech/haproxy-unified-gateway/api/gate/v3"
	"github.com/haproxytech/haproxy-unified-gateway/k8s/gate/store"
)

// onDeletedSubsystemRealIP clears the realIP configuration when the HugConf is deleted.
func (b *HugConfBuilderImpl) onDeletedSubsystemRealIP() {
	b.GateTree.RealIP = nil
}

// onUpsertedSubsystemRealIP copies the realIP spec of the HugConf into the GateTree
// (nil when the HugConf has none). The HAProxy configuration manager compares it with
// the spec it last applied, so no status tracking is needed here.
func (b *HugConfBuilderImpl) onUpsertedSubsystemRealIP(hugConfUpdate store.Update[*v3.HugConf]) {
	hugConf := hugConfUpdate.NewObject
	if hugConf == nil {
		return
	}
	b.GateTree.RealIP = hugConf.Spec.RealIP.DeepCopy()
}
