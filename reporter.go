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
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/fswalker/internal/metrics"
	fspb "github.com/google/fswalker/proto/fswalker"
)

const (
	timeReportFormat = "2006-01-02 15:04:05 MST"
)

// WalkFile contains info about a Walk file.
type WalkFile struct {
	Path        string
	Walk        *fspb.Walk
	Fingerprint *fspb.Fingerprint
}

// Report contains the result of the comparison between two Walks.
type Report struct {
	Added      []ActionData
	Deleted    []ActionData
	Modified   []ActionData
	Errors     []ActionData
	Counter    *metrics.Counter
	WalkBefore *fspb.Walk
	WalkAfter  *fspb.Walk
}

// Empty returns true if there are no additions, no deletions, no modifications and no errors.
func (r *Report) Empty() bool {
	return len(r.Added)+len(r.Deleted)+len(r.Modified)+len(r.Errors) == 0
}

// ActionData contains a diff between two files in different Walks.
type ActionData struct {
	Before *fspb.File
	After  *fspb.File
	Diff   string
	Err    error
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

// ReadWalk reads a file as marshaled proto in fspb.Walk format.
func (r *Reporter) ReadWalk(ctx context.Context, path string) (*WalkFile, error) {
	b, err := ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}
	p := &fspb.Walk{}
	if err := proto.Unmarshal(b, p); err != nil {
		return nil, err
	}
	fp := r.fingerprint(b)
	if r.Verbose {
		fmt.Printf("Loaded file %q with fingerprint: %s(%s)\n", path, fp.Method, fp.Value)
	}
	return &WalkFile{Path: path, Walk: p, Fingerprint: fp}, nil
}

// ReadLatestWalk looks for the latest Walk in a given folder for a given hostname.
// It returns the file path it ended up reading, the Walk it read and the fingerprint for it.
func (r *Reporter) ReadLatestWalk(ctx context.Context, hostname, walkPath string) (*WalkFile, error) {
	matchpath := path.Join(walkPath, WalkFilename(hostname, time.Time{}))
	names, err := Glob(ctx, matchpath)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no files found for %q", matchpath)
	}
	sort.Strings(names) // the assumption is that the file names are such that the latest is last.
	return r.ReadWalk(ctx, names[len(names)-1])
}

// ReadLastGoodWalk reads the designated review file and attempts to find an entry matching
// the given hostname. Note that if it can't find one but the review file itself was read
// successfully, it will return an empty Walk and no error.
// It returns the file path it ended up reading, the Walk it read and the fingerprint for it.
func (r *Reporter) ReadLastGoodWalk(ctx context.Context, hostname, reviewFile string) (*WalkFile, error) {
	reviews := &fspb.Reviews{}
	if err := readTextProto(ctx, reviewFile, reviews); err != nil {
		return nil, err
	}
	rvws, ok := reviews.Review[hostname]
	if !ok {
		return nil, nil
	}
	wf, err := r.ReadWalk(ctx, rvws.WalkReference)
	if err != nil {
		return wf, err
	}
	if err := r.verifyFingerprint(rvws.Fingerprint, wf.Fingerprint); err != nil {
		return wf, err
	}
	if wf.Walk.Id != rvws.WalkId {
		return wf, fmt.Errorf("walk ID doesn't match: %s (from %s) != %s (from %s)", wf.Walk.Id, rvws.WalkReference, rvws.WalkId, reviewFile)
	}
	return wf, nil
}

// ErrSameWalks is returned when comparing a walk with the same walk.
var ErrSameWalks = fmt.Errorf("Walks are the same")

// sanityCheck runs a few checks to ensure the "before" and "after" Walks are sane-ish.
func (r *Reporter) sanityCheck(before, after *fspb.Walk) error {
	if after == nil {
		return fmt.Errorf("either hostname, reviewFile and walkPath OR at least afterFile need to be specified")
	}
	if before != nil && before.Id == after.Id {
		return fmt.Errorf("ID of both Walks is %s: %w", before.Id, ErrSameWalks)
	}
	if before != nil && before.Version != after.Version {
		return fmt.Errorf("versions don't match: before(%d) != after(%d)", before.Version, after.Version)
	}
	if before != nil && before.Hostname != after.Hostname {
		return fmt.Errorf("you're comparing apples and oranges: %s != %s", before.Hostname, after.Hostname)
	}
	if before != nil {
		beforeTs := before.StopWalk.AsTime()
		afterTs := after.StartWalk.AsTime()
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

func (r *Reporter) timestampDiff(bt, at *timestamppb.Timestamp) (string, error) {
	if bt == nil && at == nil {
		return "", nil
	}
	bmt := bt.AsTime()
	amt := at.AsTime()

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
//
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
		fb := before.Fingerprint[0]
		if len(after.Fingerprint) == 0 {
			diffs = append(diffs, fmt.Sprintf("fingerprint: %s => ", fb.Value))
		} else {
			fa := after.Fingerprint[0]
			if fb.Method != fa.Method {
				diffs = append(diffs, fmt.Sprintf("fingerprint-method: %s => %s", fb.Method, fa.Method))
			}
			if fb.Value != fa.Value {
				diffs = append(diffs, fmt.Sprintf("fingerprint: %s => %s", fb.Value, fa.Value))
			}
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

// Compare two Walks and returns the diffs.
func (r *Reporter) Compare(before, after *fspb.Walk) (*Report, error) {
	if err := r.sanityCheck(before, after); err != nil {
		return nil, err
	}

	walkedBefore := map[string]*fspb.File{}
	walkedAfter := map[string]*fspb.File{}
	if before != nil {
		for _, fbOrig := range before.File {
			fb := proto.Clone(fbOrig).(*fspb.File)
			fb.Path = NormalizePath(fb.Path, fb.Info.IsDir)
			walkedBefore[fb.Path] = fb
		}
	}
	for _, faOrig := range after.File {
		fa := proto.Clone(faOrig).(*fspb.File)
		fa.Path = NormalizePath(fa.Path, fa.Info.IsDir)
		walkedAfter[fa.Path] = fa
	}

	counter := metrics.Counter{}
	output := Report{
		Counter:    &counter,
		WalkBefore: before,
		WalkAfter:  after,
	}

	for _, fb := range walkedBefore {
		counter.Add(1, "before-files")
		if r.isIgnored(fb.Path) {
			counter.Add(1, "before-files-ignored")
			continue
		}
		fa := walkedAfter[fb.Path]
		if fa == nil {
			counter.Add(1, "before-files-removed")
			output.Deleted = append(output.Deleted, ActionData{Before: fb})
			continue
		}
		diff, err := r.diffFile(fb, fa)
		if err != nil {
			counter.Add(1, "file-diff-error")
			output.Errors = append(output.Errors, ActionData{
				Before: fb,
				After:  fa,
				Diff:   diff,
				Err:    err,
			})
		}
		if diff != "" {
			counter.Add(1, "before-files-modified")
			output.Modified = append(output.Modified, ActionData{
				Before: fb,
				After:  fa,
				Diff:   diff,
			})
		}
	}
	for _, fa := range walkedAfter {
		counter.Add(1, "after-files")
		if r.isIgnored(fa.Path) {
			counter.Add(1, "after-files-ignored")
			continue
		}
		_, ok := walkedBefore[fa.Path]
		if ok {
			continue
		}
		counter.Add(1, "after-files-created")
		output.Added = append(output.Added, ActionData{After: fa})
	}
	sort.Slice(output.Added, func(i, j int) bool {
		return output.Added[i].After.Path < output.Added[j].After.Path
	})
	sort.Slice(output.Deleted, func(i, j int) bool {
		return output.Deleted[i].Before.Path < output.Deleted[j].Before.Path
	})
	sort.Slice(output.Modified, func(i, j int) bool {
		return output.Modified[i].Before.Path < output.Modified[j].Before.Path
	})
	sort.Slice(output.Errors, func(i, j int) bool {
		return output.Errors[i].Before.Path < output.Errors[j].Before.Path
	})
	return &output, nil
}

// PrintDiffSummary prints the diffs found in a Report.
func (r *Reporter) PrintDiffSummary(out io.Writer, report *Report) {
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Object Summary:")
	fmt.Fprintln(out, "===============================================================================")

	if len(report.Added) > 0 {
		fmt.Fprintf(out, "Added (%d):\n", len(report.Added))
		for _, file := range report.Added {
			fmt.Fprintln(out, file.After.Path)
		}
		fmt.Fprintln(out)
	}
	if len(report.Deleted) > 0 {
		fmt.Fprintf(out, "Removed (%d):\n", len(report.Deleted))
		for _, file := range report.Deleted {
			fmt.Fprintln(out, file.Before.Path)
		}
		fmt.Fprintln(out)
	}
	if len(report.Modified) > 0 {
		fmt.Fprintf(out, "Modified (%d):\n", len(report.Modified))
		for _, file := range report.Modified {
			fmt.Fprintln(out, file.After.Path)
			if r.Verbose {
				fmt.Fprintln(out, file.Diff)
				fmt.Fprintln(out)
			}
		}
		fmt.Fprintln(out)
	}
	if len(report.Errors) > 0 {
		fmt.Fprintf(out, "Reporting Errors (%d):\n", len(report.Errors))
		for _, file := range report.Errors {
			fmt.Fprintf(out, "%s: %v\n", file.Before.Path, file.Err)
		}
		fmt.Fprintln(out)
	}
	if report.Empty() {
		fmt.Fprintln(out, "No changes.")
	}
	if report.WalkBefore != nil && len(report.WalkBefore.Notification) > 0 {
		fmt.Fprintln(out, "Walking Errors for BEFORE file:")
		for _, err := range report.WalkBefore.Notification {
			if r.Verbose || (err.Severity != fspb.Notification_UNKNOWN && err.Severity != fspb.Notification_INFO) {
				fmt.Fprintf(out, "%s(%s): %s\n", err.Severity, err.Path, err.Message)
			}
		}
		fmt.Fprintln(out)
	}
	if len(report.WalkAfter.Notification) > 0 {
		fmt.Fprintln(out, "Walking Errors for AFTER file:")
		for _, err := range report.WalkAfter.Notification {
			if r.Verbose || (err.Severity != fspb.Notification_UNKNOWN && err.Severity != fspb.Notification_INFO) {
				fmt.Fprintf(out, "%s(%s): %s\n", err.Severity, err.Path, err.Message)
			}
		}
		fmt.Fprintln(out)
	}
}

// printWalkSummary prints some information about the given walk.
func (r *Reporter) printWalkSummary(out io.Writer, walk *fspb.Walk) {
	awst := walk.StartWalk.AsTime()
	awet := walk.StopWalk.AsTime()
	fmt.Fprintf(out, "  - ID: %s\n", walk.Id)
	fmt.Fprintf(out, "  - Start Time: %s\n", awst)
	fmt.Fprintf(out, "  - Stop Time: %s\n", awet)
}

// PrintReportSummary prints a few key information pieces around the Report.
func (r *Reporter) PrintReportSummary(out io.Writer, report *Report) {
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Report Summary:")
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintf(out, "Host name: %s\n", report.WalkAfter.Hostname)
	fmt.Fprintf(out, "Report config used: %s\n", r.configPath)
	if report.WalkBefore != nil {
		fmt.Fprintln(out, "Walk (Before)")
		r.printWalkSummary(out, report.WalkBefore)
	}
	fmt.Fprintln(out, "Walk (After)")
	r.printWalkSummary(out, report.WalkAfter)
	fmt.Fprintln(out)
}

// PrintRuleSummary prints the configs and policies involved in creating the Walk and Report.
func (r *Reporter) PrintRuleSummary(out io.Writer, report *Report) error {
	fmt.Fprintln(out, "===============================================================================")
	fmt.Fprintln(out, "Rule Summary:")
	fmt.Fprintln(out, "===============================================================================")

	if report.WalkBefore != nil {
		diff := cmp.Diff(report.WalkBefore.Policy, report.WalkAfter.Policy, cmp.Comparer(proto.Equal))
		if diff != "" {
			fmt.Fprintln(out, "Walks policy diff:")
			fmt.Fprintln(out, diff)
		} else {
			fmt.Fprintln(out, "No changes.")
		}
	}
	if r.Verbose {
		policy := report.WalkAfter.Policy
		if report.WalkBefore != nil {
			policy = report.WalkBefore.Policy
		}

		policyBytes, err := prototext.Marshal(policy)
		if err != nil {
			return err
		}
		configBytes, err := prototext.Marshal(r.config)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Policy:\n%s\nReport Config:\n%s\n", string(policyBytes), string(configBytes))
	}
	return nil
}

// UpdateReviewProto updates the reviews file to the reviewed version to be "last known good".
func (r *Reporter) UpdateReviewProto(ctx context.Context, walkFile *WalkFile, reviewFile string) error {
	review := &fspb.Review{
		WalkId:        walkFile.Walk.Id,
		WalkReference: walkFile.Path,
		Fingerprint:   walkFile.Fingerprint,
	}
	blob, err := prototext.Marshal(&fspb.Reviews{
		Review: map[string]*fspb.Review{
			walkFile.Walk.Hostname: review,
		},
	})
	if err != nil {
		return err
	}
	blobStr := string(blob)
	fmt.Println("New review section:")
	// replace message boundary characters as curly braces look nicer (both is fine to parse)
	fmt.Println(strings.Replace(strings.Replace(blobStr, "<", "{", -1), ">", "}", -1))

	if reviewFile != "" {
		reviews := &fspb.Reviews{}
		if err := readTextProto(ctx, reviewFile, reviews); err != nil {
			return err
		}

		reviews.Review[walkFile.Walk.Hostname] = review
		if err := writeTextProto(ctx, reviewFile, reviews); err != nil {
			return err
		}
		fmt.Printf("Changes written to %q\n", reviewFile)
	} else {
		fmt.Println("No reviews file provided so you will have to update it manually.")
	}
	return nil
}
