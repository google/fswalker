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

package fswalker

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/google/fswalker/internal/metrics"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"

	tspb "github.com/golang/protobuf/ptypes/timestamp"
	fspb "github.com/google/fswalker/proto/fswalker"
)

type outpathWriter string

func (o outpathWriter) writeWalk(walk *fspb.Walk) error {
	walkBytes, err := proto.Marshal(walk)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(string(o), walkBytes, 0444)
}

// testFile implements the os.FileInfo interface.
// For more details, see: https://golang.org/src/os/types.go?s=479:840#L11
type testFile struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
	sys     *syscall.Stat_t
}

func (t *testFile) Name() string       { return t.name }
func (t *testFile) Size() int64        { return t.size }
func (t *testFile) Mode() os.FileMode  { return t.mode }
func (t *testFile) ModTime() time.Time { return t.modTime }
func (t *testFile) IsDir() bool        { return t.isDir }
func (t *testFile) Sys() interface{}   { return t.sys }

func TestWalkerFromPolicyFile(t *testing.T) {
	path := filepath.Join(testdataDir, "defaultClientPolicy.asciipb")
	wantPol := &fspb.Policy{
		Version:         1,
		MaxHashFileSize: 1048576,
		Include: []string{
			"/",
		},
		ExcludePfx: []string{
			"/usr/src/linux-headers",
			"/usr/share/",
			"/proc/",
			"/sys/",
			"/tmp/",
			"/var/log/",
			"/var/tmp/",
		},
	}

	ctx := context.Background()
	wlkr, err := WalkerFromPolicyFile(ctx, path)
	if err != nil {
		t.Errorf("WalkerFromPolicyFile() error: %v", err)
		return
	}
	diff := cmp.Diff(wlkr.pol, wantPol)
	if diff != "" {
		t.Errorf("WalkerFromPolicyFile() policy: diff (-want +got):\n%s", diff)
	}
}

func TestProcess(t *testing.T) {
	ctx := context.Background()
	wlkr := &Walker{
		walk: &fspb.Walk{},
	}

	files := []*fspb.File{
		{},
		{},
		{},
	}
	for _, f := range files {
		if err := wlkr.process(ctx, f); err != nil {
			t.Errorf("process() error: %v", err)
			continue
		}
	}
	if diff := cmp.Diff(wlkr.walk.File, files); diff != "" {
		t.Errorf("wlkr.walk.File != files: diff (-want +got):\n%s", diff)
	}
}

func TestIsExcluded(t *testing.T) {
	testCases := []struct {
		desc     string
		excludes []string
		wantExcl bool
	}{
		{
			desc:     "test exclusion with empty list",
			excludes: []string{},
			wantExcl: false,
		}, {
			desc: "test exclusion with entries but no match",
			excludes: []string{
				"/tmp/",
				"/home/user2/",
				"/var/log/",
			},
			wantExcl: false,
		}, {
			desc: "test exclusion with entries and exact match",
			excludes: []string{
				"/tmp/",
				"/home/user/secret",
				"/var/log/",
			},
			wantExcl: true,
		}, {
			desc: "test exclusion with entries and prefix match",
			excludes: []string{
				"/tmp/",
				"/home/user",
				"/var/log/",
			},
			wantExcl: true,
		},
	}

	const path = "/home/user/secret"
	for _, tc := range testCases {
		wlkr := &Walker{
			pol: &fspb.Policy{
				ExcludePfx: tc.excludes,
			},
		}

		gotExcl := wlkr.isExcluded(path)
		if gotExcl != tc.wantExcl {
			t.Errorf("isExcluded() %q = %v; want %v", tc.desc, gotExcl, tc.wantExcl)
		}
	}
}

func TestWantHashing(t *testing.T) {
	testCases := []struct {
		desc      string
		hashpttrn []string
		wantHash  bool
	}{
		{
			desc:      "test exclusion with empty list",
			hashpttrn: []string{},
			wantHash:  false,
		}, {
			desc: "test exclusion with entries but no match",
			hashpttrn: []string{
				"/tmp/",
				"/home/user2/",
				"/var/log/",
			},
			wantHash: false,
		}, {
			desc: "test exclusion with entries and exact match",
			hashpttrn: []string{
				"/tmp/",
				"/home/user/secret",
				"/var/log/",
			},
			wantHash: true,
		}, {
			desc: "test exclusion with entries and prefix match",
			hashpttrn: []string{
				"/tmp/",
				"/home/user",
				"/var/log/",
			},
			wantHash: true,
		},
	}

	const path = "/home/user/secret"
	for _, tc := range testCases {
		wlkr := &Walker{
			pol: &fspb.Policy{
				HashPfx: tc.hashpttrn,
			},
		}

		gotHash := wlkr.wantHashing(path)
		if gotHash != tc.wantHash {
			t.Errorf("wantHashing() %q = %v; want %v", tc.desc, gotHash, tc.wantHash)
		}
	}
}

func TestConvert(t *testing.T) {
	wlkr := &Walker{
		pol: &fspb.Policy{
			HashPfx: []string{
				testdataDir,
			},
			MaxHashFileSize: 1048576,
		},
	}
	path := filepath.Join(testdataDir, "hashSumTest")
	info := &testFile{
		name:    "hashSumTest",
		size:    100,
		mode:    os.FileMode(640),
		modTime: time.Now(),
		isDir:   false,
		sys: &syscall.Stat_t{
			Dev:     1,
			Ino:     123456,
			Nlink:   2,
			Mode:    640,
			Uid:     123,
			Gid:     456,
			Rdev:    111,
			Size:    100,
			Blksize: 128,
			Blocks:  10,
			Atim:    syscall.Timespec{time.Now().Unix(), 100},
			Mtim:    syscall.Timespec{time.Now().Unix(), 200},
			Ctim:    syscall.Timespec{time.Now().Unix(), 300},
		},
	}

	mts, _ := ptypes.TimestampProto(info.ModTime())
	wantFile := &fspb.File{
		Version: 1,
		Path:    path,
		Info: &fspb.FileInfo{
			Name:     "hashSumTest",
			Size:     100,
			Mode:     640,
			Modified: mts,
			IsDir:    false,
		},
		Stat: &fspb.FileStat{
			Dev:     1,
			Inode:   123456,
			Nlink:   2,
			Mode:    640,
			Uid:     123,
			Gid:     456,
			Rdev:    111,
			Size:    100,
			Blksize: 128,
			Blocks:  10,
			Atime:   &tspb.Timestamp{Seconds: info.sys.Atim.Sec, Nanos: 100},
			Mtime:   &tspb.Timestamp{Seconds: info.sys.Mtim.Sec, Nanos: 200},
			Ctime:   &tspb.Timestamp{Seconds: info.sys.Ctim.Sec, Nanos: 300},
		},
		Fingerprint: []*fspb.Fingerprint{
			{
				Method: fspb.Fingerprint_SHA256,
				Value:  "aeb02544df0ef515b21cab81ad5c0609b774f86879bf7e2e42c88efdaab2c75f",
			},
		},
	}

	gotFile := wlkr.convert(path, nil) // ensuring there is no problems with nil file stats.
	if wantFile.Path != gotFile.Path {
		t.Errorf("convert() path = %q; want: %q", gotFile.Path, wantFile.Path)
	}

	gotFile = wlkr.convert(path, info)
	diff := cmp.Diff(gotFile, wantFile)
	if diff != "" {
		t.Errorf("convert() File proto: diff (-want +got):\n%s", diff)
	}
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	tmpfile, err := ioutil.TempFile("", "walk.pb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	writer := outpathWriter(tmpfile.Name())
	wlkr := &Walker{
		pol: &fspb.Policy{
			Include: []string{
				testdataDir,
			},
			HashPfx: []string{
				testdataDir,
			},
			MaxHashFileSize: 1048576,
		},
		WalkCallback: writer.writeWalk,
		Counter:      &metrics.Counter{},
	}

	if err := wlkr.Run(ctx); err != nil {
		t.Errorf("Run() error: %v", err)
		return
	}

	wantMetrics := []string{
		"dir-count",
		"file-size-sum",
		"file-count",
		"file-hash-count",
	}
	sort.Strings(wantMetrics)
	m := wlkr.Counter.Metrics()
	sort.Strings(m)
	if !reflect.DeepEqual(wantMetrics, m) {
		t.Errorf("wlkr.Counter.Metrics() = %q; want %q", m, wantMetrics)
	}
	for _, k := range m {
		if _, ok := wlkr.Counter.Get(k); !ok {
			t.Errorf("wlkr.Counter.Get(%q): not ok", k)
		}
	}

	b, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Errorf("unable to read file %q: %v", tmpfile.Name(), err)
	}
	walk := &fspb.Walk{}
	if err := proto.Unmarshal(b, walk); err != nil {
		t.Errorf("unabled to decode proto file %q: %v", tmpfile.Name(), err)
	}
	st, err := ptypes.Timestamp(walk.StartWalk)
	if err != nil {
		t.Errorf("walk.StartWalk: unable to decode start timestamp: %v", err)
	}
	et, err := ptypes.Timestamp(walk.StopWalk)
	if err != nil {
		t.Errorf("walk.StopWalk: unable to decode stop timestamp: %v", err)
	}
	if st.Before(time.Now().Add(-time.Hour)) || st.After(et) {
		t.Errorf("start time is not within bounds: %s < %s < %s", time.Now().Add(-time.Hour), st, et)
	}
	if et.Before(st) || et.After(time.Now()) {
		t.Errorf("stop time is not within bounds: %s < %s < %s", st, et, time.Now())
	}
	if walk.Hostname == "" {
		t.Error("walk.Hostname is empty")
	}
	if walk.Id == "" {
		t.Error("walk.Id is empty")
	}
}
