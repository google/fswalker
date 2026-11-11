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
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"

	fspb "github.com/google/fswalker/proto/fswalker"
)

const (
	testdataDir = "testdata"
)

func TestWalkFilename(t *testing.T) {
	testCases := []struct {
		h        string
		t        time.Time
		wantFile string
	}{
		{
			h:        "test-host.google.com",
			t:        time.Date(2018, 12, 06, 10, 01, 02, 0, time.UTC),
			wantFile: "test-host.google.com-20181206-100102-fswalker-state.pb",
		}, {
			h:        "test-host.google.com",
			wantFile: "test-host.google.com-*-fswalker-state.pb",
		}, {
			t:        time.Date(2018, 12, 06, 10, 01, 02, 0, time.UTC),
			wantFile: "*-20181206-100102-fswalker-state.pb",
		}, {
			wantFile: "*-*-fswalker-state.pb",
		},
	}

	for _, tc := range testCases {
		gotFile := WalkFilename(tc.h, tc.t)
		if gotFile != tc.wantFile {
			t.Errorf("WalkFilename(%s, %s) = %q; want: %q", tc.h, tc.t, gotFile, tc.wantFile)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		// arguments
		path  string
		isDir bool
		// expected return value
		ret string
	}{
		{"/a/b", true, "/a/b/"},
		{"/a/b/", true, "/a/b/"},
		{"/a/b//", true, "/a/b/"},
		{"/a/b", false, "/a/b"},
		{"/a/b/", false, "/a/b"},
		{"/a/b//", false, "/a/b"},
		{"/", false, "/"},
		{"/", true, "/"},
	}
	for _, x := range tests {
		p := filepath.FromSlash(x.path)
		expected := filepath.FromSlash(x.ret)
		got := NormalizePath(p, x.isDir)
		if got != expected {
			t.Errorf("NormalizePath(%q, %v) = %q; want: %q", p, x.isDir, got, expected)
		}
	}
}

func mustSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", path, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func TestSha256sum(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello world")
	testFilePath := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(testFilePath, content, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", testFilePath, err)
	}
	emptyPath := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", emptyPath, err)
	}
	symlinkPath := filepath.Join(dir, "link")
	if err := os.Symlink(testFilePath, symlinkPath); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", testFilePath, symlinkPath, err)
	}
	fifoPath := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatalf("syscall.Mkfifo(%q) failed: %v", fifoPath, err)
	}

	fileSize := int64(len(content))
	for _, tc := range []struct {
		name     string
		path     string
		maxBytes int64
		want     string
		wantErr  error
	}{
		{name: "within_limit", path: testFilePath, maxBytes: 1048576, want: mustSHA256(t, testFilePath)},
		{name: "exact_limit", path: testFilePath, maxBytes: fileSize, want: mustSHA256(t, testFilePath)},
		{name: "zero_limit_empty_file", path: emptyPath, maxBytes: 0, want: mustSHA256(t, emptyPath)},
		{name: "negative_max_bytes", path: testFilePath, maxBytes: -1, wantErr: cmpopts.AnyError},
		{name: "exceeds_max_bytes", path: testFilePath, maxBytes: fileSize - 1, wantErr: cmpopts.AnyError},
		{name: "nonexistent_file", path: filepath.Join(dir, "missing"), maxBytes: 1024, wantErr: cmpopts.AnyError},
		{name: "symlink", path: symlinkPath, maxBytes: 1024, wantErr: cmpopts.AnyError},
		{name: "fifo", path: fifoPath, maxBytes: 1024, wantErr: cmpopts.AnyError},
		{name: "directory", path: dir, maxBytes: 1024, wantErr: cmpopts.AnyError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sha256sum(tc.path, tc.maxBytes)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("sha256sum(%q, %d) error = %v, want %v", tc.path, tc.maxBytes, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("sha256sum(%q, %d) = %q, want %q", tc.path, tc.maxBytes, got, tc.want)
			}
		})
	}
}

func TestReadTextProtoReviews(t *testing.T) {
	ctx := context.Background()
	wantReviews := &fspb.Reviews{
		Review: map[string]*fspb.Review{
			"host-A.google.com": {
				WalkId:        "debffdde-47f3-454b-adaa-d79d95945c69",
				WalkReference: "/some/file/path/hostA_20180922_state.pb",
				Fingerprint: &fspb.Fingerprint{
					Method: fspb.Fingerprint_SHA256,
					Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
				},
			},
			"host-B.google.com": {
				WalkId:        "2bd40596-d7da-423c-9bb9-c682ebc23f75",
				WalkReference: "/some/file/path/hostB_20180810_state.pb",
				Fingerprint: &fspb.Fingerprint{
					Method: fspb.Fingerprint_SHA256,
					Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
				},
			},
			"host-C.google.com": {
				WalkId:        "caf8192e-834f-4cd4-a216-fa6f7871ad41",
				WalkReference: "/some/file/path/hostC_20180922_state.pb",
				Fingerprint: &fspb.Fingerprint{
					Method: fspb.Fingerprint_SHA256,
					Value:  "5669df6b2f003ca61714b1b9830c41cf3a2ebe644abb2516db3021c20a1b7483",
				},
			},
		},
	}
	reviews := &fspb.Reviews{}
	if err := readTextProto(ctx, filepath.Join(testdataDir, "reviews.asciipb"), reviews); err != nil {
		t.Errorf("readTextProto() error: %v", err)
	}
	diff := cmp.Diff(reviews, wantReviews, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("readTextProto(): unexpected content: diff (-want +got):\n%s", diff)
	}
}

func TestReadTextProtoConfigs(t *testing.T) {
	ctx := context.Background()
	wantConfig := &fspb.ReportConfig{
		Version: 1,
		ExcludePfx: []string{
			"/usr/src/linux-headers",
			"/usr/share/",
			"/proc/",
			"/tmp/",
			"/var/log/",
			"/var/tmp/",
		},
	}
	config := &fspb.ReportConfig{}
	if err := readTextProto(ctx, filepath.Join(testdataDir, "defaultReportConfig.asciipb"), config); err != nil {
		t.Fatalf("readTextProto(): %v", err)
	}
	diff := cmp.Diff(config, wantConfig, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("readTextProto(): unexpected content: diff (-want +got):\n%s", diff)
	}
}

func TestReadPolicy(t *testing.T) {
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
	pol := &fspb.Policy{}
	if err := readTextProto(ctx, filepath.Join(testdataDir, "defaultClientPolicy.asciipb"), pol); err != nil {
		t.Errorf("readTextProto() error: %v", err)
		return
	}
	diff := cmp.Diff(pol, wantPol, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("readTextProto() policy: diff (-want +got): \n%s", diff)
	}
}

func TestWriteTextProtoReviews(t *testing.T) {
	wantReviews := &fspb.Reviews{
		Review: map[string]*fspb.Review{
			"hostname": &fspb.Review{
				WalkId:        "id",
				WalkReference: "reference",
				Fingerprint: &fspb.Fingerprint{
					Method: fspb.Fingerprint_SHA256,
					Value:  "fingerprint",
				},
			},
		},
	}

	tmpfile, err := os.CreateTemp("", "review.asciipb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	ctx := context.Background()
	if err := writeTextProto(ctx, tmpfile.Name(), wantReviews); err != nil {
		t.Errorf("writeTextProto() error: %v", err)
	}

	gotReviews := &fspb.Reviews{}
	if err := readTextProto(ctx, tmpfile.Name(), gotReviews); err != nil {
		t.Errorf("readTextProto() error: %v", err)
	}
	diff := cmp.Diff(gotReviews, wantReviews, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("writeTextProto() reviews: diff (-want +got): \n%s", diff)
	}
}
