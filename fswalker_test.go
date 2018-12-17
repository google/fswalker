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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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

func TestSha256sum(t *testing.T) {
	gotHash, err := sha256sum(filepath.Join(testdataDir, "hashSumTest"))
	if err != nil {
		t.Errorf("sha256sum() error: %v", err)
		return
	}
	const wantHash = "aeb02544df0ef515b21cab81ad5c0609b774f86879bf7e2e42c88efdaab2c75f"
	if gotHash != wantHash {
		t.Errorf("sha256sum() = %q; want: %q", gotHash, wantHash)
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
	diff := cmp.Diff(reviews, wantReviews)
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
	diff := cmp.Diff(config, wantConfig)
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
	diff := cmp.Diff(pol, wantPol)
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

	tmpfile, err := ioutil.TempFile("", "review.asciipb")
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
	diff := cmp.Diff(gotReviews, wantReviews)
	if diff != "" {
		t.Errorf("writeTextProto() reviews: diff (-want +got): \n%s", diff)
	}
}
