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
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	fspb "github.com/google/fswalker/proto/fswalker"
)

func TestVerifyFingerprint(t *testing.T) {
	testCases := []struct {
		desc    string
		goodFp  *fspb.Fingerprint
		checkFp *fspb.Fingerprint
		wantErr bool
	}{
		{
			desc: "pass with all good values",
			goodFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			checkFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			wantErr: false,
		}, {
			desc: "pass but not ok with all different values",
			goodFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			checkFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7484",
			},
			wantErr: true,
		}, {
			desc: "fail with different fingerprinting methods",
			goodFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			checkFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_UNKNOWN,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			wantErr: true,
		}, {
			desc: "fail with unknown fingerprinting method",
			goodFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_UNKNOWN,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			checkFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_UNKNOWN,
				Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
			},
			wantErr: true,
		}, {
			desc: "fail with empty fingerprint value",
			goodFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "",
			},
			checkFp: &fspb.Fingerprint{
				Method: fspb.Fingerprint_SHA256,
				Value:  "",
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		r := &Reporter{}
		t.Run(tc.desc, func(t *testing.T) {
			err := r.verifyFingerprint(tc.goodFp, tc.checkFp)
			switch {
			case tc.wantErr && err == nil:
				t.Error("verifyFingerprint() returned nil error")
			case !tc.wantErr && err != nil:
				t.Errorf("verifyFingerprint(): %v", err)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	b := []byte("test string")
	wantFp := "d5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b"
	r := &Reporter{}
	fp := r.fingerprint(b)
	if fp.Method != fspb.Fingerprint_SHA256 {
		t.Errorf("fingerprint().Method: got=%v, want=SHA256", fp.Value)
	}
	if fp.Value != wantFp {
		t.Errorf("fingerprint().Value: got=%s, want=%s", fp.Value, wantFp)
	}
}

func TestReadWalk(t *testing.T) {
	ctx := context.Background()
	wantWalk := &fspb.Walk{
		Id:        "",
		Version:   1,
		Hostname:  "testhost",
		StartWalk: timestamppb.Now(),
		StopWalk:  timestamppb.Now(),
		Policy: &fspb.Policy{
			Version: 1,
			Include: []string{
				"/",
			},
			ExcludePfx: []string{
				"/var/log/",
				"/home/",
				"/tmp/",
			},
			HashPfx: []string{
				"/etc/",
			},
			MaxHashFileSize: 1024 * 1024,
		},
		File: []*fspb.File{
			{
				Version: 1,
				Path:    "/etc/test",
				Info: &fspb.FileInfo{
					Name:  "hashSumTest",
					Size:  100,
					Mode:  640,
					IsDir: false,
				},
				Fingerprint: []*fspb.Fingerprint{
					{
						Method: fspb.Fingerprint_SHA256,
						Value:  "deadbeef",
					},
				},
			},
		},
	}

	walkBytes, err := proto.Marshal(wantWalk)
	if err != nil {
		t.Fatalf("problems marshaling walk: %v", err)
	}

	tmpfile, err := os.CreateTemp("", "walk.pb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	if _, err := tmpfile.Write(walkBytes); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	h := sha256.New()
	h.Write(walkBytes)
	wantFp := fmt.Sprintf("%x", h.Sum(nil))

	r := &Reporter{}
	got, err := r.ReadWalk(ctx, tmpfile.Name())
	if err != nil {
		t.Fatalf("readwalk(): %v", err)
	}
	if got.Fingerprint.Method != fspb.Fingerprint_SHA256 {
		t.Errorf("readwalk(): fingerprint method, got=%v, want=SHA256", got.Fingerprint.Method)
	}
	if got.Fingerprint.Value != wantFp {
		t.Errorf("readwalk(): fingerprint value, got=%s, want=%s", got.Fingerprint.Value, wantFp)
	}
	diff := cmp.Diff(got.Walk, wantWalk, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("readwalk(): content diff (-want +got):\n%s", diff)
	}
}

func TestSanityCheck(t *testing.T) {
	ts1:= timestamppb.Now()
	ts2:= timestamppb.New(time.Now().Add(time.Hour * 10))
	ts3:= timestamppb.New(time.Now().Add(time.Hour * 20))
	testCases := []struct {
		before  *fspb.Walk
		after   *fspb.Walk
		wantErr error
	}{
		{
			before:  &fspb.Walk{},
			after:   &fspb.Walk{},
			wantErr: ErrSameWalks,
		}, {
			before:  nil,
			after:   &fspb.Walk{},
			wantErr: nil,
		}, {
			before:  &fspb.Walk{},
			after:   nil,
			wantErr: cmpopts.AnyError,
		}, {
			before: &fspb.Walk{},
			after: &fspb.Walk{
				Id: "unique2",
			},
			wantErr: nil,
		}, {
			before: &fspb.Walk{
				Id:        "unique1",
				Version:   1,
				Hostname:  "testhost1",
				StartWalk: ts1,
				StopWalk:  ts1,
			},
			after: &fspb.Walk{
				Id:        "unique2",
				Version:   1,
				Hostname:  "testhost1",
				StartWalk: ts2,
				StopWalk:  ts3,
			},
			wantErr: nil,
		}, {
			before: nil,
			after: &fspb.Walk{
				Id:        "unique2",
				Version:   1,
				Hostname:  "testhost1",
				StartWalk: ts2,
				StopWalk:  ts3,
			},
			wantErr: nil,
		}, {
			before: &fspb.Walk{
				Id:      "unique1",
				Version: 1,
			},
			after: &fspb.Walk{
				Id:      "unique2",
				Version: 2,
			},
			wantErr: cmpopts.AnyError,
		}, {
			before: &fspb.Walk{
				Id:        "unique1",
				StartWalk: ts1,
				StopWalk:  ts2,
			},
			after: &fspb.Walk{
				Id:        "unique2",
				StartWalk: ts1,
				StopWalk:  ts3,
			},
			wantErr: cmpopts.AnyError,
		}, {
			before: &fspb.Walk{
				Id:       "unique1",
				Hostname: "testhost1",
			},
			after: &fspb.Walk{
				Id:       "unique2",
				Hostname: "testhost2",
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		r := &Reporter{}
		err := r.sanityCheck(tc.before, tc.after)
		if !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
			t.Errorf("sanityCheck() = %v, want %v", err, tc.wantErr)
		}
	}
}

func TestIsIgnored(t *testing.T) {
	conf := &fspb.ReportConfig{
		Version: 1,
		ExcludePfx: []string{
			"/tmp/",
			"/var/log/",
		},
	}
	testCases := []struct {
		path   string
		wantIg bool
	}{
		{
			path:   "/tmp/something",
			wantIg: true,
		}, {
			path:   "/tmp/",
			wantIg: true,
		}, {
			path:   "/tmp",
			wantIg: false,
		}, {
			path:   "/tmp2/file",
			wantIg: false,
		}, {
			path:   "/home/someone",
			wantIg: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			r := &Reporter{
				config: conf,
			}
			gotIg := r.isIgnored(tc.path)
			if gotIg != tc.wantIg {
				t.Errorf("isIgnored() ignore: got=%t, want=%t", gotIg, tc.wantIg)
			}
		})
	}
}

func TestDiffFile(t *testing.T) {
	testCases := []struct {
		desc     string
		before   *fspb.File
		after    *fspb.File
		wantDiff string
		wantErr  bool
	}{
		{
			desc:     "same empty files",
			before:   &fspb.File{},
			after:    &fspb.File{},
			wantDiff: "",
		}, {
			desc: "same non-empty files",
			before: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size:     1000,
					Mode:     644,
					Modified: &timestamppb.Timestamp{},
				},
			},
			after: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size:     1000,
					Mode:     644,
					Modified: &timestamppb.Timestamp{},
				},
			},
			wantDiff: "",
		}, {
			desc: "file info changes mode and mtime",
			before: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size: 1000,
					Mode: 644,
					Modified: &timestamppb.Timestamp{
						Seconds: int64(1543831000),
					},
				},
			},
			after: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size: 1000,
					Mode: 744,
					Modified: &timestamppb.Timestamp{
						Seconds: int64(1543931000),
					},
				},
			},
			wantDiff: "mode: 644 => 744\nmtime: 2018-12-03 09:56:40 UTC => 2018-12-04 13:43:20 UTC",
		}, {
			desc: "file stat changes uid and ctime",
			before: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Stat: &fspb.FileStat{
					Uid: uint32(5000),
					Ctime: &timestamppb.Timestamp{
						Seconds: int64(1543831000),
					},
				},
			},
			after: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Stat: &fspb.FileStat{
					Uid: uint32(0),
					Ctime: &timestamppb.Timestamp{
						Seconds: int64(1543931000),
					},
				},
			},
			wantDiff: "ctime: 2018-12-03 09:56:40 UTC => 2018-12-04 13:43:20 UTC\nuid: 5000 => 0",
		}, {
			desc: "file changes version",
			before: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size: 1000,
					Mode: 644,
				},
			},
			after: &fspb.File{
				Version: 2,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size: 1000,
					Mode: 644,
				},
			},
			wantErr: true,
		}, {
			desc: "no fingerprint after",
			before: &fspb.File{
				Path:        "/tmp/testfile",
				Fingerprint: []*fspb.Fingerprint{&fspb.Fingerprint{Value: "abcd"}},
			},
			after: &fspb.File{
				Path: "/tmp/testfile",
			},
			wantDiff: "fingerprint: abcd => ",
		}, {
			desc: "diff fingerprints",
			before: &fspb.File{
				Path:        "/tmp/testfile",
				Fingerprint: []*fspb.Fingerprint{&fspb.Fingerprint{Value: "abcd"}},
			},
			after: &fspb.File{
				Path:        "/tmp/testfile",
				Fingerprint: []*fspb.Fingerprint{&fspb.Fingerprint{Value: "efgh"}},
			},
			wantDiff: "fingerprint: abcd => efgh",
		}, {
			desc: "fingerprint only after",
			before: &fspb.File{
				Path: "/tmp/testfile",
			},
			after: &fspb.File{
				Path:        "/tmp/testfile",
				Fingerprint: []*fspb.Fingerprint{&fspb.Fingerprint{Value: "abcd"}},
			},
			wantDiff: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r := &Reporter{}
			gotDiff, err := r.diffFile(tc.before, tc.after)
			switch {
			case tc.wantErr && err == nil:
				t.Error("diffFile() no error")
			case !tc.wantErr && err != nil:
				t.Errorf("diffFile() error: %v", err)
			default:
				if gotDiff != tc.wantDiff {
					t.Errorf("diffFile() diff: got=%q, want=%q", gotDiff, tc.wantDiff)
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	testCases := []struct {
		desc      string
		before    *fspb.Walk
		after     *fspb.Walk
		deleted   int
		added     int
		modified  int
		wantError bool
	}{
		{
			desc:   "nil before",
			before: nil,
			after: &fspb.Walk{
				File: []*fspb.File{
					&fspb.File{Path: "/a/b/c", Info: &fspb.FileInfo{}},
				},
			},
			added: 1,
		}, {
			desc: "empty after",
			before: &fspb.Walk{
				Id: "1",
				File: []*fspb.File{
					&fspb.File{Path: "/a/b/c", Info: &fspb.FileInfo{}},
				},
			},
			after:   &fspb.Walk{Id: "2"},
			deleted: 1,
		}, {
			desc:      "nil before and after",
			before:    nil,
			after:     nil,
			wantError: true,
		}, {
			desc: "diffs",
			before: &fspb.Walk{
				Id: "1",
				File: []*fspb.File{
					&fspb.File{Path: "/a/b/c", Info: &fspb.FileInfo{}},
					&fspb.File{Path: "/e/f/g", Info: &fspb.FileInfo{Size: 4}},
					&fspb.File{Path: "/x/y/z", Info: &fspb.FileInfo{}},
				},
			},
			after: &fspb.Walk{
				Id: "2",
				File: []*fspb.File{
					&fspb.File{Path: "/b/c/d", Info: &fspb.FileInfo{}},
					&fspb.File{Path: "/e/f/g", Info: &fspb.FileInfo{Size: 7}},
					&fspb.File{Path: "/x/y/z", Info: &fspb.FileInfo{}},
				},
			},
			added:    1,
			deleted:  1,
			modified: 1,
		}, {
			desc: "ignore",
			before: &fspb.Walk{
				Id: "1",
				File: []*fspb.File{
					&fspb.File{Path: "/ignore/a", Info: &fspb.FileInfo{}},
				},
			},
			after: &fspb.Walk{
				Id: "2",
				File: []*fspb.File{
					&fspb.File{Path: "/ignore/b", Info: &fspb.FileInfo{}},
				},
			},
		}, {
			desc: "same dir with and without trailing /",
			before: &fspb.Walk{
				Id: "1",
				File: []*fspb.File{
					&fspb.File{Path: "/a/b/c/", Info: &fspb.FileInfo{IsDir: true}},
				},
			},
			after: &fspb.Walk{
				Id: "2",
				File: []*fspb.File{
					&fspb.File{Path: "/a/b/c", Info: &fspb.FileInfo{IsDir: true}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r := &Reporter{config: &fspb.ReportConfig{ExcludePfx: []string{"/ignore/"}}}
			report, err := r.Compare(tc.before, tc.after)
			switch {
			case tc.wantError && err == nil:
				t.Error("Compare() no error")
			case !tc.wantError && err != nil:
				t.Errorf("Compare() error: %v", err)
			case err == nil:
				if n := len(report.Added); n != tc.added {
					t.Errorf("len(report.Added) = %d; want %d", n, tc.added)
				}
				if n := len(report.Deleted); n != tc.deleted {
					t.Errorf("len(report.Deleted) = %d; want %d", n, tc.deleted)
				}
				if n := len(report.Modified); n != tc.modified {
					t.Errorf("len(report.Modified) = %d; want %d", n, tc.modified)
				}
			}
		})
	}
}
