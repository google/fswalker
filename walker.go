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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"

	"github.com/google/fswalker/internal/fsstat"
	"github.com/google/fswalker/internal/metrics"
	fspb "github.com/google/fswalker/proto/fswalker"
)

const (
	// Number of root paths to walk in parallel.
	parallelism = 1

	// Versions for compatibility comparison.
	fileVersion = 1
	walkVersion = 1

	// Unique names for each counter - used by the counter output processor.
	countFiles       = "file-count"
	countDirectories = "dir-count"
	countFileSizeSum = "file-size-sum"
	countStatErr     = "file-stat-errors"
	countHashes      = "file-hash-count"
)

// WalkCallback is called by Walker at the end of the Run.
// The callback is typically used to dump the walk to disk and/or perform any other checks.
// The error return value is propagated back to the Run callers.
type WalkCallback func(context.Context, *fspb.Walk) error

// WalkerFromPolicyFile creates a new Walker based on a policy path.
func WalkerFromPolicyFile(ctx context.Context, path string) (*Walker, error) {
	pol := &fspb.Policy{}
	if err := readTextProto(ctx, path, pol); err != nil {
		return nil, err
	}
	return &Walker{
		pol:     pol,
		Counter: &metrics.Counter{},
	}, nil
}

// Walker is able to walk a file structure starting with a list of given includes
// as roots. All paths starting with any prefix specified in the excludes are
// ignored. The list of specific files in the hash list are read and a hash sum
// built for each. Note that this is expensive and should not be done for large
// files or a large number of files.
type Walker struct {
	// pol is the configuration defining which paths to include and exclude from the walk.
	pol *fspb.Policy

	// walk collects all processed files during a run.
	walk   *fspb.Walk
	walkMu sync.Mutex

	// Function to call once the Walk is complete i.e. to inspect or write the Walk.
	WalkCallback WalkCallback

	// Verbose, when true, makes Walker print file metadata to stdout.
	Verbose bool

	// Counter records stats over all processed files, if non-nil.
	Counter *metrics.Counter
}

// convert creates a File from the given information and if requested embeds the hash sum too.
func (w *Walker) convert(path string, info os.FileInfo) (*fspb.File, error) {
	path = filepath.Clean(path)

	f := &fspb.File{
		Version: fileVersion,
		Path:    path,
	}

	if info == nil {
		return f, nil
	}

	var shaSum string
	// Only build the hash sum if requested and if it is not a directory.
	if w.wantHashing(path) && !info.IsDir() && info.Size() <= w.pol.MaxHashFileSize {
		var err error
		shaSum, err = sha256sum(path)
		if err != nil {
			log.Printf("unable to build hash for %s: %s", path, err)
		} else {
			f.Fingerprint = []*fspb.Fingerprint{
				{
					Method: fspb.Fingerprint_SHA256,
					Value:  shaSum,
				},
			}
		}
	}

	mts, _ := ptypes.TimestampProto(info.ModTime()) // ignoring the error and using default
	f.Info = &fspb.FileInfo{
		Name:     info.Name(),
		Size:     info.Size(),
		Mode:     uint32(info.Mode()),
		Modified: mts,
		IsDir:    info.IsDir(),
	}

	var err error
	if f.Stat, err = fsstat.ToStat(info); err != nil {
		return nil, err
	}

	return f, nil
}

// wantHashing determines whether the given path was asked to be hashed.
func (w *Walker) wantHashing(path string) bool {
	for _, p := range w.pol.HashPfx {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// isExcluded determines whether a given path was asked to be excluded from scanning.
func (w *Walker) isExcluded(path string) bool {
	for _, e := range w.pol.ExcludePfx {
		if strings.HasPrefix(path, e) {
			return true
		}
	}
	return false
}

// process runs output functions for the given input File.
func (w *Walker) process(ctx context.Context, f *fspb.File) error {
	// Print a short overview if we're running in verbose mode.
	if w.Verbose {
		fmt.Println(NormalizePath(f.Path, f.Info.IsDir))
		ts, _ := ptypes.Timestamp(f.Info.Modified) // ignoring error in ts conversion
		info := []string{
			fmt.Sprintf("size(%d)", f.Info.Size),
			fmt.Sprintf("mode(%v)", os.FileMode(f.Info.Mode)),
			fmt.Sprintf("mTime(%v)", ts),
			fmt.Sprintf("uid(%d)", f.Stat.Uid),
			fmt.Sprintf("gid(%d)", f.Stat.Gid),
			fmt.Sprintf("inode(%d)", f.Stat.Inode),
		}
		for _, fp := range f.Fingerprint {
			info = append(info, fmt.Sprintf("%s(%s)", fspb.Fingerprint_Method_name[int32(fp.Method)], fp.Value))
		}
		fmt.Println(strings.Join(info, ", "))
	}

	// Add file to the walk which will later be written out to disk.
	w.addFileToWalk(f)

	// Collect some metrics.
	if w.Counter != nil {
		if f.Info.IsDir {
			w.Counter.Add(1, countDirectories)
		} else {
			w.Counter.Add(1, countFiles)
		}
		w.Counter.Add(f.Info.Size, countFileSizeSum)
		if f.Stat == nil {
			w.Counter.Add(1, countStatErr)
		}
		if len(f.Fingerprint) > 0 {
			w.Counter.Add(1, countHashes)
		}
	}

	return nil
}

func (w *Walker) addFileToWalk(f *fspb.File) {
	w.walkMu.Lock()
	w.walk.File = append(w.walk.File, f)
	w.walkMu.Unlock()
}

func (w *Walker) addNotificationToWalk(s fspb.Notification_Severity, path, msg string) {
	w.walkMu.Lock()
	w.walk.Notification = append(w.walk.Notification, &fspb.Notification{
		Severity: s,
		Path:     path,
		Message:  msg,
	})
	w.walkMu.Unlock()
}

// relDirDepth calculates the path depth relative to the origin.
func (w *Walker) relDirDepth(origin, path string) uint32 {
	return uint32(len(strings.Split(path, string(filepath.Separator))) - len(strings.Split(origin, string(filepath.Separator))))
}

// worker is a worker routine that reads paths from chPaths and walks all the files and
// subdirectories until the channel is exhausted. All discovered files are converted to
// File and processed with w.process().
func (w *Walker) worker(ctx context.Context, chPaths <-chan string) error {
	for path := range chPaths {
		baseInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to get file info for base path %q: %v", path, err)
		}
		baseDev, err := fsstat.DevNumber(baseInfo)
		if err != nil {
			return fmt.Errorf("unable to get file stat on base path %q: %v", path, err)
		}
		if err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			p = NormalizePath(p, info.IsDir())
			if err != nil {
				msg := fmt.Sprintf("failed to walk %q: %s", p, err)
				log.Printf(msg)
				w.addNotificationToWalk(fspb.Notification_WARNING, p, msg)
				return nil // returning SkipDir on a file would skip the rest of the files in the dir
			}

			// Checking various exclusions based on flags in the walker policy.
			if w.isExcluded(p) {
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, fmt.Sprintf("skipping %q: excluded", p))
				}
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil // returning SkipDir on a file would skip the rest of the files in the dir
			}
			if w.pol.IgnoreIrregularFiles && !info.Mode().IsRegular() && !info.IsDir() {
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, fmt.Sprintf("skipping %q: irregular file (mode: %s)", p, info.Mode()))
				}
				return nil
			}
			f, err := w.convert(p, info)
			if err != nil {
				return err
			}
			if w.pol.MaxDirectoryDepth > 0 && info.IsDir() && w.relDirDepth(path, p) > w.pol.MaxDirectoryDepth {
				w.addNotificationToWalk(fspb.Notification_WARNING, p, fmt.Sprintf("skipping %q: more than %d into base path %q", p, w.pol.MaxDirectoryDepth, path))
				return filepath.SkipDir
			}
			if !w.pol.WalkCrossDevice && f.Stat != nil && baseDev != f.Stat.Dev {
				msg := fmt.Sprintf("skipping %q: file is on different device", p)
				log.Printf(msg)
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, msg)
				}
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil // returning SkipDir on a file would skip the rest of the files in the dir
			}

			return w.process(ctx, f)
		}); err != nil {
			return fmt.Errorf("error walking root include path %q: %v", path, err)
		}
	}
	return nil
}

// Run is the main function of Walker. It discovers all files under included paths
// (minus excluded ones) and processes them.
// This does NOT follow symlinks - fortunately we don't need it either.
func (w *Walker) Run(ctx context.Context) error {
	walkID := uuid.New().String()
	hn, err := os.Hostname()
	if err != nil {
		return err
	}
	w.walk = &fspb.Walk{
		Version:   walkVersion,
		Id:        walkID,
		Policy:    w.pol,
		Hostname:  hn,
		StartWalk: ptypes.TimestampNow(),
	}

	chPaths := make(chan string, 10)
	var wg sync.WaitGroup
	var errs []string
	var errsMu sync.Mutex
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.worker(ctx, chPaths); err != nil {
				errsMu.Lock()
				errs = append(errs, err.Error())
				errsMu.Unlock()
			}
		}()
	}

	includes := map[string]bool{}
	for _, p := range w.pol.Include {
		p := filepath.Clean(p)
		if _, ok := includes[p]; ok {
			continue
		}
		includes[p] = true
		chPaths <- p
	}
	close(chPaths)
	wg.Wait()
	if len(errs) != 0 {
		return fmt.Errorf("unable to complete Walk:\n%s", strings.Join(errs, "\n"))
	}

	// Finishing work by writing out the report.
	w.walk.StopWalk = ptypes.TimestampNow()
	if w.WalkCallback == nil {
		return nil
	}
	return w.WalkCallback(ctx, w.walk)
}
