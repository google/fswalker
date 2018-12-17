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
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"

	tspb "github.com/golang/protobuf/ptypes/timestamp"
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
		StartWalk: ptypes.TimestampNow(),
		StopWalk:  ptypes.TimestampNow(),
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

	tmpfile, err := ioutil.TempFile("", "walk.pb")
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
	gotWalk, fp, err := r.readWalk(ctx, tmpfile.Name())
	if err != nil {
		t.Fatalf("readwalk(): %v", err)
	}
	if fp.Method != fspb.Fingerprint_SHA256 {
		t.Errorf("readwalk(): fingerprint method, got=%v, want=SHA256", fp.Method)
	}
	if fp.Value != wantFp {
		t.Errorf("readwalk(): fingerprint value, got=%s, want=%s", fp.Value, wantFp)
	}
	diff := cmp.Diff(gotWalk, wantWalk, cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Contains(p.String(), "XXX_")
	}, cmp.Ignore()))
	if diff != "" {
		t.Errorf("readwalk(): content diff (-want +got):\n%s", diff)
	}
}

func TestSanityCheck(t *testing.T) {
	ts1, _ := ptypes.TimestampProto(time.Now())
	ts2, _ := ptypes.TimestampProto(time.Now().Add(time.Hour * 10))
	ts3, _ := ptypes.TimestampProto(time.Now().Add(time.Hour * 20))
	testCases := []struct {
		before  *fspb.Walk
		after   *fspb.Walk
		wantErr bool
	}{
		{
			before:  &fspb.Walk{},
			after:   &fspb.Walk{},
			wantErr: true,
		}, {
			before:  nil,
			after:   &fspb.Walk{},
			wantErr: false,
		}, {
			before:  &fspb.Walk{},
			after:   nil,
			wantErr: true,
		}, {
			before: &fspb.Walk{},
			after: &fspb.Walk{
				Id: "unique2",
			},
			wantErr: false,
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
			wantErr: false,
		}, {
			before: nil,
			after: &fspb.Walk{
				Id:        "unique2",
				Version:   1,
				Hostname:  "testhost1",
				StartWalk: ts2,
				StopWalk:  ts3,
			},
			wantErr: false,
		}, {
			before: &fspb.Walk{
				Id:      "unique1",
				Version: 1,
			},
			after: &fspb.Walk{
				Id:      "unique2",
				Version: 2,
			},
			wantErr: true,
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
			wantErr: true,
		}, {
			before: &fspb.Walk{
				Id:       "unique1",
				Hostname: "testhost1",
			},
			after: &fspb.Walk{
				Id:       "unique2",
				Hostname: "testhost2",
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		r := &Reporter{}
		err := r.sanityCheck(tc.before, tc.after)
		if err != nil && !tc.wantErr {
			t.Errorf("sanityCheck() error: %v", err)
		}
		if err == nil && tc.wantErr {
			t.Error("sanityCheck() no error")
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
					Modified: &tspb.Timestamp{},
				},
			},
			after: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Info: &fspb.FileInfo{
					Size:     1000,
					Mode:     644,
					Modified: &tspb.Timestamp{},
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
					Modified: &tspb.Timestamp{
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
					Modified: &tspb.Timestamp{
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
					Ctime: &tspb.Timestamp{
						Seconds: int64(1543831000),
					},
				},
			},
			after: &fspb.File{
				Version: 1,
				Path:    "/tmp/testfile",
				Stat: &fspb.FileStat{
					Uid: uint32(0),
					Ctime: &tspb.Timestamp{
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
					t.Errorf("diffFile() diff: got=%s, want=%s", gotDiff, tc.wantDiff)
				}
			}
		})
	}
}
