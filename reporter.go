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
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/fswalker/internal/metrics"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"

	tspb "github.com/golang/protobuf/ptypes/timestamp"
	fspb "github.com/google/fswalker/proto/fswalker"
)

const (
	actionAdd    = action("Added")
	actionModify = action("Modified")
	actionDelete = action("Deleted")
	actionError  = action("Error")

	timeReportFormat = "2006-01-02 15:04:05 MST"
)

type action string

type actionData struct {
	before *fspb.File
	after  *fspb.File
	diff   string
	err    error
}

// ReporterFromConfigFile creates a new Reporter based on a config path.
func ReporterFromConfigFile(ctx context.Context, path string, verbose bool) (*Reporter, error) {
	config := &fspb.ReportConfig{}
	if err := readTextProto(ctx, path, config); err != nil {
		return nil, err
	}
	return &Reporter{
		config:     config,
		configPath: path,
		Verbose:    verbose,
		Counter:    &metrics.Counter{},
	}, nil
}

// Reporter compares two Walks against each other based on the config provided
// and prints a list of diffs between the two.
type Reporter struct {
	// config is the configuration defining paths to exclude from the report as well as other aspects.
	config     *fspb.ReportConfig
	configPath string

	// Verbose, when true, makes Reporter print more information for all diffs found.
	Verbose bool

	// Counter records stats over all processed files, if non-nil.
	Counter *metrics.Counter

	reviewFile string
	reviews    *fspb.Reviews

	beforeFile string
	before     *fspb.Walk
	beforeFp   *fspb.Fingerprint
	afterFile  string
	after      *fspb.Walk
	afterFp    *fspb.Fingerprint
}

func (r *Reporter) verifyFingerprint(goodFp *fspb.Fingerprint, checkFp *fspb.Fingerprint) error {
	if checkFp.Method != goodFp.Method {
		return fmt.Errorf("fingerprint method %q doesn't match %q", checkFp.Method, goodFp.Method)
	}
	if goodFp.Method == fspb.Fingerprint_UNKNOWN {
		return errors.New("undefined fingerprint method")
	}
	if goodFp.Value == "" {
		return errors.New("empty fingerprint value")
	}
	if checkFp.Value != goodFp.Value {
		return fmt.Errorf("fingerprint %q doesn't match %q", checkFp.Value, goodFp.Value)
	}
	return nil
}

func (r *Reporter) fingerprint(b []byte) *fspb.Fingerprint {
	v := fmt.Sprintf("%x", sha256.Sum256(b))
	return &fspb.Fingerprint{
		Method: fspb.Fingerprint_SHA256,
		Value:  v,
	}
}

// readWalk reads a file as marshaled proto in fspb.Walk format.
func (r *Reporter) readWalk(ctx context.Context, path string) (*fspb.Walk, *fspb.Fingerprint, error) {
	b, err := ReadFile(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	p := &fspb.Walk{}
	if err := proto.Unmarshal(b, p); err != nil {
		return nil, nil, err
	}
	fp := r.fingerprint(b)
	fmt.Printf("Loaded file %q with fingerprint: %s(%s)\n", path, fp.Method, fp.Value)
	return p, fp, nil
}

// loadLatestWalk looks for the latest Walk in a given folder for a given hostname.
// It returns the file path it ended up reading, the Walk it read and the fingerprint for it.
func (r *Reporter) loadLatestWalk(ctx context.Context, hostname, walkPath string) (string, *fspb.Walk, *fspb.Fingerprint, error) {
	matchpath := path.Join(walkPath, WalkFilename(hostname, time.Time{}))
	names, err := Glob(ctx, matchpath)
	if err != nil {
		return "", nil, nil, err
	}
	if len(names) == 0 {
		return "", nil, nil, fmt.Errorf("no files found for %q", matchpath)
	}
	sort.Strings(names) // the assumption is that the file names are such that the latest is last.
	wlk, fp, err := r.readWalk(ctx, names[len(names)-1])
	return names[len(names)-1], wlk, fp, err
}

// loadLastGoodWalk reads the designated review file and attempts to find an entry matching
// the given hostname. Note that if it can't find one but the review file itself was read
// successfully, it will return an empty Walk and no error.
// It returns the file path it ended up reading, the Walk it read and the fingerprint for it.
func (r *Reporter) loadLastGoodWalk(ctx context.Context, hostname, reviewFile string) (string, *fspb.Walk, *fspb.Fingerprint, error) {
	r.reviews = &fspb.Reviews{}
	if err := readTextProto(ctx, reviewFile, r.reviews); err != nil {
		return "", nil, nil, err
	}
	rvws, ok := r.reviews.Review[hostname]
	if !ok {
		return "", nil, nil, nil
	}
	good, fp, err := r.readWalk(ctx, rvws.WalkReference)
	if err != nil {
		return "", nil, nil, err
	}
	if err := r.verifyFingerprint(rvws.Fingerprint, fp); err != nil {
		return "", nil, nil, err
	}
	if good.Id != rvws.WalkId {
		return "", nil, fp, fmt.Errorf("walk ID doesn't match: %s (from %s) != %s (from %s)", good.Id, rvws.WalkReference, rvws.WalkId, reviewFile)
	}
	return rvws.WalkReference, good, fp, nil
}

// LoadWalks accepts a number of parameters on which it decides how to load the walks to compare.
// Note that the "before" walk (i.e. last known good) may be legitimately empty.
func (r *Reporter) LoadWalks(ctx context.Context, hostname, reviewFile, walkPath, afterFile, beforeFile string) error {
	var err error
	var before, after *fspb.Walk
	var beforeFp, afterFp *fspb.Fingerprint
	if hostname != "" && reviewFile != "" && walkPath != "" {
		if afterFile != "" || beforeFile != "" {
			return fmt.Errorf("[hostname reviewFile walkPath] and [beforeFile afterFile] are mutually exclusive")
		}

		beforeFile, before, beforeFp, err = r.loadLastGoodWalk(ctx, hostname, reviewFile)
		if err != nil {
			return fmt.Errorf("unable to load last good walk for %s: %v", hostname, err)
		}
		afterFile, after, afterFp, err = r.loadLatestWalk(ctx, hostname, walkPath)
		if err != nil {
			return fmt.Errorf("unable to load latest walk for %s: %v", hostname, err)
		}
		if err := r.sanityCheck(before, after); err != nil {
			return err
		}
		r.reviewFile = reviewFile
		r.before = before
		r.beforeFp = beforeFp
		r.beforeFile = beforeFile
		r.after = after
		r.afterFp = afterFp
		r.afterFile = afterFile
		return nil
	}

	if afterFile != "" {
		after, afterFp, err = r.readWalk(ctx, afterFile)
		if err != nil {
			return fmt.Errorf("File cannot be read: %s", afterFile)
		}
		if beforeFile != "" {
			before, beforeFp, err = r.readWalk(ctx, beforeFile)
			if err != nil {
				return fmt.Errorf("File cannot be read: %s", beforeFile)
			}
		}
		if err := r.sanityCheck(before, after); err != nil {
			return err
		}
		r.before = before
		r.beforeFp = beforeFp
		r.beforeFile = beforeFile
		r.after = after
		r.afterFp = afterFp
		r.afterFile = afterFile
		return nil
	}

	return fmt.Errorf("either [hostname reviewFile walkPath] OR [[beforeFile] afterFile] need to be specified")
}

// sanityCheck runs a few checks to ensure the "before" and "after" Walks are sane-ish.
func (r *Reporter) sanityCheck(before, after *fspb.Walk) error {
	if after == nil {
		return fmt.Errorf("either hostname, reviewFile and walkPath OR at least afterFile need to be specified")
	}
	if before != nil && before.Id == after.Id {
		return fmt.Errorf("ID of both Walks is the same: %s", before.Id)
	}
	if before != nil && before.Version != after.Version {
		return fmt.Errorf("versions don't match: before(%d) != after(%d)", before.Version, after.Version)
	}
	if before != nil && before.Hostname != after.Hostname {
		return fmt.Errorf("you're comparing apples and oranges: %s != %s", before.Hostname, after.Hostname)
	}
	if before != nil {
		beforeTs, _ := ptypes.Timestamp(before.StopWalk)
		afterTs, _ := ptypes.Timestamp(after.StartWalk)
		if beforeTs.After(afterTs) {
			return fmt.Errorf("earlier Walk indicates it ended (%s) after later Walk (%s) has started", beforeTs, afterTs)
		}
	}
	return nil
}

// isIgnored checks for a given file path whether it is ignored by the report config or not.
func (r *Reporter) isIgnored(path string) bool {
	for _, i := range r.config.ExcludePfx {
		if strings.HasPrefix(path, i) {
			return true
		}
	}
	return false
}

func (r *Reporter) timestampDiff(bt, at *tspb.Timestamp) (string, error) {
	if bt == nil && at == nil {
		return "", nil
	}
	bmt, err := ptypes.Timestamp(bt)
	if err != nil {
		return "", err
	}
	amt, err := ptypes.Timestamp(at)
	if err != nil {
		return "", err
	}
	if bmt.Equal(amt) {
		return "", nil
	}
	return fmt.Sprintf("%s => %s", bmt.Format(timeReportFormat), amt.Format(timeReportFormat)), nil
}

// diffFileStat compares the FileInfo proto of two files and reports all relevant diffs as human readable strings.
func (r *Reporter) diffFileInfo(fib, fia *fspb.FileInfo) ([]string, error) {
	var diffs []string

	if fib == nil && fia == nil {
		return diffs, nil
	}

	if fib.Name != fia.Name {
		diffs = append(diffs, fmt.Sprintf("name: %q => %q", fib.Name, fia.Name))
	}
	if fib.Size != fia.Size {
		diffs = append(diffs, fmt.Sprintf("size: %d => %d", fib.Size, fia.Size))
	}
	if fib.Mode != fia.Mode {
		diffs = append(diffs, fmt.Sprintf("mode: %d => %d", fib.Mode, fia.Mode))
	}
	if fib.IsDir != fia.IsDir {
		diffs = append(diffs, fmt.Sprintf("is_dir: %t => %t", fib.IsDir, fia.IsDir))
	}

	// Ignore if both timestamps are nil.
	if fib.Modified == nil && fia.Modified == nil {
		return diffs, nil
	}
	diff, err := r.timestampDiff(fib.Modified, fia.Modified)
	if err != nil {
		return diffs, fmt.Errorf("unable to convert timestamps for %q: %v", fib.Name, err)
	}
	if diff != "" {
		diffs = append(diffs, fmt.Sprintf("mtime: %s", diff))
	}

	return diffs, nil
}

// diffFileStat compares the FileStat proto of two files and reports all relevant diffs as human readable strings.
// The following fields are ignored as they are not regarded as relevant in this context:
//   - atime
//   - inode, nlink, dev, rdev
//   - blksize, blocks
// The following fields are ignored as they are already part of diffFileInfo() check
// which is more guaranteed to be available (to avoid duplicate output):
//   - mode
//   - size
//   - mtime
func (r *Reporter) diffFileStat(fsb, fsa *fspb.FileStat) ([]string, error) {
	var diffs []string

	if fsb == nil && fsa == nil {
		return diffs, nil
	}

	if fsb.Uid != fsa.Uid {
		diffs = append(diffs, fmt.Sprintf("uid: %d => %d", fsb.Uid, fsa.Uid))
	}
	if fsb.Gid != fsa.Gid {
		diffs = append(diffs, fmt.Sprintf("gid: %d => %d", fsb.Gid, fsa.Gid))
	}

	// Ignore ctime changes if mtime equals to ctime or if both are nil.
	cdiff, cerr := r.timestampDiff(fsb.Ctime, fsa.Ctime)
	if cerr != nil {
		return diffs, fmt.Errorf("unable to convert timestamps: %v", cerr)
	}
	if cdiff == "" {
		return diffs, nil
	}
	mdiff, merr := r.timestampDiff(fsb.Mtime, fsa.Mtime)
	if merr != nil {
		return diffs, fmt.Errorf("unable to convert timestamps: %v", merr)
	}
	if mdiff != cdiff {
		diffs = append(diffs, fmt.Sprintf("ctime: %s", cdiff))
	}

	return diffs, nil
}

// diffFile compares two File entries of a Walk and shows the diffs between the two.
func (r *Reporter) diffFile(before, after *fspb.File) (string, error) {
	if before.Version != after.Version {
		return "", fmt.Errorf("file format versions don't match: before(%d) != after(%d)", before.Version, after.Version)
	}
	if before.Path != after.Path {
		return "", fmt.Errorf("file paths don't match: before(%q) != after(%q)", before.Path, after.Path)
	}

	var diffs []string
	// Ensure fingerprints are the same - if there was one before. Do not show a diff if there's a new fingerprint.
	if len(before.Fingerprint) > 0 {
		if diff := cmp.Diff(before.Fingerprint, after.Fingerprint); diff != "" {
			diffs = append(diffs, diff)
		}
	}
	fiDiffs, err := r.diffFileInfo(before.Info, after.Info)
	if err != nil {
		return "", fmt.Errorf("unable to diff file info for %q: %v", before.Path, err)
	}
	diffs = append(diffs, fiDiffs...)
	fsDiffs, err := r.diffFileStat(before.Stat, after.Stat)
	if err != nil {
		return "", fmt.Errorf("unable to diff file stat for %q: %v", before.Path, err)
	}
	diffs = append(diffs, fsDiffs...)
	sort.Strings(diffs)
	return strings.Join(diffs, "\n"), nil
}

func (r *Reporter) count(metric string) {
	if r.Counter == nil {
		return
	}
	r.Counter.Add(1, metric)
}

// Compare runs through two Walks (before and after) with a given ReportConfig and shows the diffs.
func (r *Reporter) Compare(out io.Writer) {
	// Processing report.
	output := map[action][]actionData{}
	walkedBefore := map[string]*fspb.File{}
	walkedAfter := map[string]*fspb.File{}

	if r.before != nil {
		for _, fb := range r.before.File {
			walkedBefore[fb.Path] = fb
		}
	}
	for _, fa := range r.after.File {
		walkedAfter[fa.Path] = fa
	}

	if r.before != nil {
		for _, fb := range r.before.File {
			r.count("before-files")
			if r.isIgnored(fb.Path) {
				r.count("before-files-ignored")
				continue
			}
			fa := walkedAfter[fb.Path]
			if fa == nil {
				r.count("before-files-removed")
				output[actionDelete] = append(output[actionDelete], actionData{before: fb})
				continue
			}
			diff, err := r.diffFile(fb, fa)
			if err != nil {
				r.count("file-diff-error")
				output[actionError] = append(output[actionError], actionData{
					before: fb,
					after:  fa,
					diff:   diff,
					err:    err,
				})
			}
			if diff != "" {
				r.count("before-files-modified")
				output[actionModify] = append(output[actionModify], actionData{
					before: fb,
					after:  fa,
					diff:   diff,
				})
			}
		}
	}
	for _, fa := range r.after.File {
		r.count("after-files")
		if r.isIgnored(fa.Path) {
			r.count("after-files-ignored")
			continue
		}
		_, ok := walkedBefore[fa.Path]
		if ok {
			continue
		}
		r.count("after-files-created")
		output[actionAdd] = append(output[actionAdd], actionData{after: fa})
	}

	// Writing sorted output.
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Object Summary:")
	fmt.Fprintln(out, "===============================================================================")
	if len(output[actionAdd]) > 0 {
		fmt.Fprintf(out, "Added (%d):\n", len(output[actionAdd]))
		for _, file := range output[actionAdd] {
			fmt.Fprintln(out, file.after.Path)
		}
		fmt.Fprintln(out)
	}
	if len(output[actionDelete]) > 0 {
		fmt.Fprintf(out, "Removed (%d):\n", len(output[actionDelete]))
		for _, file := range output[actionDelete] {
			fmt.Fprintln(out, file.before.Path)
		}
		fmt.Fprintln(out)
	}
	if len(output[actionModify]) > 0 {
		fmt.Fprintf(out, "Modified (%d):\n", len(output[actionModify]))
		for _, file := range output[actionModify] {
			fmt.Fprintln(out, file.after.Path)
			if r.Verbose {
				fmt.Fprintln(out, file.diff)
				fmt.Fprintln(out)
			}
		}
		fmt.Fprintln(out)
	}
	if len(output[actionError]) > 0 {
		fmt.Fprintf(out, "Reporting Errors (%d):\n", len(output[actionError]))
		for _, file := range output[actionError] {
			fmt.Fprintf(out, "%s: %v\n", file.before.Path, file.err)
		}
		fmt.Fprintln(out)
	}
	if r.before != nil && len(r.before.Notification) > 0 {
		fmt.Fprintln(out, "Walking Errors for BEFORE file:")
		for _, err := range r.before.Notification {
			if r.Verbose || (err.Severity != fspb.Notification_UNKNOWN && err.Severity != fspb.Notification_INFO) {
				fmt.Fprintf(out, "%s(%s): %s\n", err.Severity, err.Path, err.Message)
			}
		}
		fmt.Fprintln(out)
	}
	if len(r.after.Notification) > 0 {
		fmt.Fprintln(out, "Walking Errors for AFTER file:")
		for _, err := range r.after.Notification {
			if r.Verbose || (err.Severity != fspb.Notification_UNKNOWN && err.Severity != fspb.Notification_INFO) {
				fmt.Fprintf(out, "%s(%s): %s\n", err.Severity, err.Path, err.Message)
			}
		}
		fmt.Fprintln(out)
	}
}

// PrintReportSummary prints a few key information pieces around the Report.
func (r *Reporter) PrintReportSummary(out io.Writer) {
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Report Summary:")
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Host name: %s\n", r.after.Hostname)
	fmt.Fprintf(out, "Report config used: %s\n", r.configPath)

	if r.before != nil {
		bwst, err := ptypes.Timestamp(r.before.StartWalk)
		if err != nil {
			log.Fatalf("unable to convert before walk start timestamp: %v", err)
		}
		bwet, err := ptypes.Timestamp(r.before.StopWalk)
		if err != nil {
			log.Fatalf("unable to convert before walk stop timestamp: %v", err)
		}
		fmt.Fprintln(out, "Walk (Before)")
		fmt.Fprintf(out, "  - ID: %s\n", r.before.Id)
		fmt.Fprintf(out, "  - Start Time: %s\n", bwst)
		fmt.Fprintf(out, "  - Stop Time: %s\n", bwet)
	}

	awst, err := ptypes.Timestamp(r.after.StartWalk)
	if err != nil {
		log.Fatalf("unable to convert after walk start timestamp: %v", err)
	}
	awet, err := ptypes.Timestamp(r.after.StopWalk)
	if err != nil {
		log.Fatalf("unable to convert after walk stop timestamp: %v", err)
	}
	fmt.Fprintln(out, "Walk (After)")
	fmt.Fprintf(out, "  - ID: %s\n", r.after.Id)
	fmt.Fprintf(out, "  - Start Time: %s\n", awst)
	fmt.Fprintf(out, "  - Stop Time: %s\n", awet)
	fmt.Fprintln(out)
}

// PrintRuleSummary prints the configs and policies involved in creating the Walk and Report.
func (r *Reporter) PrintRuleSummary(out io.Writer) {
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Rule Summary:")
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Client Policy:")
	if r.before == nil {
		fmt.Fprintln(out, proto.MarshalTextString(r.after.Policy))
	} else {
		diff := cmp.Diff(r.before.Policy, r.after.Policy)
		if diff != "" {
			fmt.Fprintln(out, "Diff:")
			fmt.Fprintln(out, diff)
			fmt.Fprintln(out, "Before:")
		}
		fmt.Fprintln(out, proto.MarshalTextString(r.before.Policy))
	}
	fmt.Fprintln(out, "Report Config:")
	fmt.Fprintln(out, proto.MarshalTextString(r.config))
}

// UpdateReviewProto updates the reviews file to the reviewed version to be "last known good".
func (r *Reporter) UpdateReviewProto(ctx context.Context) error {
	review := &fspb.Review{
		WalkId:        r.after.Id,
		WalkReference: r.afterFile,
		Fingerprint:   r.afterFp,
	}
	blob := proto.MarshalTextString(&fspb.Reviews{
		Review: map[string]*fspb.Review{
			r.after.Hostname: review,
		},
	})
	fmt.Println("New review section:")
	// replace message boundary characters as curly braces look nicer (both is fine to parse)
	fmt.Println(strings.Replace(strings.Replace(blob, "<", "{", -1), ">", "}", -1))
	if r.reviewFile != "" && r.reviews != nil {
		r.reviews.Review[r.after.Hostname] = review
		if err := writeTextProto(ctx, r.reviewFile, r.reviews); err != nil {
			return err
		}
		fmt.Printf("Changes written to %q\n", r.reviewFile)
	} else {
		fmt.Println("No reviews file provided so you will have to update it manually.")
	}
	return nil
}
