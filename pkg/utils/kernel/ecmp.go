// Copyright 2019-2026 The Liqo Authors
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

package kernel

import "os"

const ecmpFile = "/proc/sys/net/ipv4/fib_multipath_hash_policy"

// Enable Ecmp hash filtering on the 5-tuple.
// It writes 1 to /proc/sys/net/ipv4/fib_multipath_hash_policy.
func EnableEcmp() error {
	file, err := os.OpenFile(ecmpFile, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString("1\n"); err != nil {
		return err
	}
	return nil
}