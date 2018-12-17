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

// Package metrics implements generic metrics.
package metrics

import "sync"

// Counter keeps count of metrics for parallel running routines.
type Counter struct {
	mu     sync.RWMutex
	counts map[string]int64
}

// Add adds count to metric. If metric doesn't exist, it creates it.
func (c *Counter) Add(count int64, metric string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.counts == nil {
		c.counts = make(map[string]int64)
	}

	c.counts[metric] += count
}

// Metrics returns a slice of metrics which are tracked.
func (c *Counter) Metrics() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var metrics []string
	for m := range c.counts {
		metrics = append(metrics, m)
	}

	return metrics
}

// Get returns the value of a specific metric based on its name as well
// as a bool indicating the value was read successfully.
func (c *Counter) Get(name string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.counts[name]
	return val, ok
}
