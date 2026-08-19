//
// Copyright 2023 The Sigstore Authors.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yckms

import "testing"

func FuzzParseReference(f *testing.F) {
	f.Add("/key-id-123")
	f.Add("kms.yandexcloud.net/folder/folder-1/keyname/releases")
	f.Add("")
	f.Add("yckms:///key-id-123")
	f.Fuzz(func(_ *testing.T, ref string) {
		_, _, _, _, _ = ParseReference(ref)
		_ = ValidReference(ref)
	})
}
