// Copyright 2018 Google LLC
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

package metrics

import (
	"sync"
	"testing"
)

func TestCounter(t *testing.T) {
	const wantCount = int64(100)
	const wantMetric = "test-counter"
	c := &Counter{}

	var wg sync.WaitGroup
	for i := int64(0); i < wantCount; i++ {
		wg.Add(1)
		go func() {
			c.Add(1, wantMetric)
			wg.Done()
		}()
	}
	wg.Wait()

	if n, ok := c.Get(wantMetric); n != wantCount || !ok {
		t.Errorf("c.Get(%q) = %d, %v; want %d, true", wantMetric, n, ok, wantCount)
	}

	m := c.Metrics()
	if len(m) != 1 {
		t.Errorf("len(c.Metrics()) = %d; want 1", len(m))
	}
	if m[0] != wantMetric {
		t.Errorf("c.Metrics()[0] = %q; want %q", m[0], wantMetric)
	}
}
